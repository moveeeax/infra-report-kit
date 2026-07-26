package adapter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

// sensitivePorts are the ports where "open to 0.0.0.0/0" is a critical finding
// rather than an architectural choice someone might defend.
var sensitivePorts = map[int]string{
	22:    "SSH",
	23:    "Telnet",
	135:   "MSRPC",
	445:   "SMB",
	1433:  "MSSQL",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5984:  "CouchDB",
	6379:  "Redis",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

// sgAudit consumes aws-sg-audit output: security groups with world-open rules.
//
// Input shape:
//
//	{"account":"123456789012",
//	 "security_groups":[{"group_id":"sg-0a1b","group_name":"web","region":"eu-west-1",
//	   "vpc_id":"vpc-01","open_ingress":[{"protocol":"tcp","from_port":22,"to_port":22,"cidr":"0.0.0.0/0"}]}]}
type sgAudit struct{}

func (sgAudit) Name() string { return "aws-sg-audit" }

func (a sgAudit) Parse(raw []byte, r *model.Report) error {
	var in struct {
		Account string `json:"account"`
		Groups  []struct {
			GroupID     string `json:"group_id"`
			GroupName   string `json:"group_name"`
			Region      string `json:"region"`
			VPCID       string `json:"vpc_id"`
			OpenIngress []struct {
				Protocol string `json:"protocol"`
				FromPort int    `json:"from_port"`
				ToPort   int    `json:"to_port"`
				CIDR     string `json:"cidr"`
			} `json:"open_ingress"`
		} `json:"security_groups"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("aws-sg-audit: %w", err)
	}
	for _, g := range in.Groups {
		if len(g.OpenIngress) == 0 {
			continue
		}
		sev := model.SeverityHigh
		var exposed []string
		for _, rule := range g.OpenIngress {
			label, portSev := classifyRule(rule.Protocol, rule.FromPort, rule.ToPort)
			if portSev.Rank() > sev.Rank() {
				sev = portSev
			}
			exposed = append(exposed, fmt.Sprintf("%s %s from %s", strings.ToUpper(rule.Protocol), label, rule.CIDR))
		}
		sort.Strings(exposed)
		r.Add(model.Finding{
			Source:   a.Name(),
			Section:  model.SectionSecurity,
			Rule:     "world-open-ingress",
			Severity: sev,
			Title:    fmt.Sprintf("Security group %s (%s) accepts traffic from the internet", g.GroupID, g.GroupName),
			Detail:   strings.Join(exposed, "; "),
			Recommendation: "Replace the 0.0.0.0/0 source with the office CIDR, a VPN range or a " +
				"prefix list, or front the service with a load balancer.",
			Resource: model.Resource{
				Provider: "aws", Account: account(in.Account, r), Region: g.Region,
				Type: "ec2:security-group", ID: g.GroupID, Name: g.GroupName,
			},
			Evidence: compact(map[string]string{
				"vpc_id":     g.VPCID,
				"open_rules": strconv.Itoa(len(g.OpenIngress)),
			}),
		})
	}
	return nil
}

// classifyRule names the exposed port range and grades it. A range that spans
// more than one port is treated as critical regardless of which ports it hits,
// because "all ports open to the world" is never a considered decision.
func classifyRule(proto string, from, to int) (string, model.Severity) {
	if proto == "-1" || strings.EqualFold(proto, "all") || (from == 0 && to == 0) {
		return "all ports", model.SeverityCritical
	}
	if from != to {
		return fmt.Sprintf("ports %d-%d", from, to), model.SeverityCritical
	}
	if name, ok := sensitivePorts[from]; ok {
		return fmt.Sprintf("port %d (%s)", from, name), model.SeverityCritical
	}
	return fmt.Sprintf("port %d", from), model.SeverityHigh
}

// s3PublicAudit consumes s3-public-audit output.
//
// Input shape:
//
//	{"account":"123456789012",
//	 "buckets":[{"name":"acme-assets","region":"eu-west-1","public_acl":true,
//	   "public_policy":false,"block_public_access":false,"public_objects":12}]}
type s3PublicAudit struct{}

func (s3PublicAudit) Name() string { return "s3-public-audit" }

func (a s3PublicAudit) Parse(raw []byte, r *model.Report) error {
	var in struct {
		Account string `json:"account"`
		Buckets []struct {
			Name              string `json:"name"`
			Region            string `json:"region"`
			PublicACL         bool   `json:"public_acl"`
			PublicPolicy      bool   `json:"public_policy"`
			BlockPublicAccess bool   `json:"block_public_access"`
			PublicObjects     int    `json:"public_objects"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("s3-public-audit: %w", err)
	}
	for _, b := range in.Buckets {
		public := b.PublicACL || b.PublicPolicy
		if !public && b.BlockPublicAccess {
			continue // locked down, nothing to report
		}
		var reasons []string
		if b.PublicACL {
			reasons = append(reasons, "public ACL")
		}
		if b.PublicPolicy {
			reasons = append(reasons, "public bucket policy")
		}
		if !b.BlockPublicAccess {
			reasons = append(reasons, "Block Public Access disabled")
		}

		sev := model.SeverityMedium
		rule := "block-public-access-off"
		title := fmt.Sprintf("Bucket %s is not protected by Block Public Access", b.Name)
		if public {
			sev = model.SeverityCritical
			rule = "public-bucket"
			title = fmt.Sprintf("Bucket %s is readable from the internet", b.Name)
		}
		r.Add(model.Finding{
			Source:   a.Name(),
			Section:  model.SectionSecurity,
			Rule:     rule,
			Severity: sev,
			Title:    title,
			Detail:   strings.Join(reasons, ", "),
			Recommendation: "Enable Block Public Access at the bucket and account level, then serve " +
				"anything genuinely public through CloudFront with an origin access identity.",
			Resource: model.Resource{
				Provider: "aws", Account: account(in.Account, r), Region: b.Region,
				Type: "s3:bucket", ID: b.Name,
			},
			Evidence: compact(map[string]string{
				"public_objects": itoaIfPositive(b.PublicObjects),
			}),
		})
	}
	return nil
}

// iamLeastPriv consumes aws-iam-least-priv output.
//
// Input shape:
//
//	{"account":"123456789012",
//	 "principals":[{"arn":"arn:aws:iam::123456789012:role/Deploy","name":"Deploy","type":"role",
//	   "admin":true,"last_used_days":210,"attached_policies":["AdministratorAccess"],
//	   "unused_services":["rds","kms"]}]}
type iamLeastPriv struct{}

func (iamLeastPriv) Name() string { return "aws-iam-least-priv" }

func (a iamLeastPriv) Parse(raw []byte, r *model.Report) error {
	var in struct {
		Account    string `json:"account"`
		Principals []struct {
			ARN              string   `json:"arn"`
			Name             string   `json:"name"`
			Type             string   `json:"type"`
			Admin            bool     `json:"admin"`
			LastUsedDays     int      `json:"last_used_days"`
			AttachedPolicies []string `json:"attached_policies"`
			UnusedServices   []string `json:"unused_services"`
		} `json:"principals"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("aws-iam-least-priv: %w", err)
	}
	for _, p := range in.Principals {
		var sev model.Severity
		var rule, title, detail string
		switch {
		case p.Admin && p.LastUsedDays >= 90:
			sev, rule = model.SeverityCritical, "dormant-admin"
			title = fmt.Sprintf("Admin %s %s has not been used for %d days", p.Type, p.Name, p.LastUsedDays)
			detail = fmt.Sprintf("Holds %s; last activity %d days ago.",
				strings.Join(p.AttachedPolicies, ", "), p.LastUsedDays)
		case p.Admin:
			sev, rule = model.SeverityHigh, "standing-admin"
			title = fmt.Sprintf("%s %s holds standing administrator access", titleCase(p.Type), p.Name)
			detail = fmt.Sprintf("Holds %s.", strings.Join(p.AttachedPolicies, ", "))
		case len(p.UnusedServices) > 0:
			sev, rule = model.SeverityLow, "unused-permissions"
			title = fmt.Sprintf("%s %s can reach %d services it never uses", titleCase(p.Type), p.Name, len(p.UnusedServices))
			detail = "Never used: " + strings.Join(p.UnusedServices, ", ")
		default:
			continue
		}
		r.Add(model.Finding{
			Source:   a.Name(),
			Section:  model.SectionSecurity,
			Rule:     rule,
			Severity: sev,
			Title:    title,
			Detail:   detail,
			Recommendation: "Replace the broad policy with one generated from the last 90 days of " +
				"Access Advisor data, and move break-glass admin behind a separate assumed role.",
			Resource: model.Resource{
				Provider: "aws", Account: account(in.Account, r),
				Type: "iam:" + p.Type, ID: p.ARN, Name: p.Name,
			},
			Evidence: compact(map[string]string{
				"last_used_days":  itoaIfPositive(p.LastUsedDays),
				"unused_services": strings.Join(p.UnusedServices, ","),
			}),
		})
	}
	return nil
}

// certCheck consumes certcheck output. Only certificates inside the warning
// window reach the report; a certificate with four months left is not news.
//
// Input shape:
//
//	{"certificates":[{"subject":"api.example.com","issuer":"R3","not_after":"2026-08-01T00:00:00Z",
//	   "days_remaining":6,"origin":"acm","identifier":"arn:aws:acm:...","region":"eu-west-1"}]}
type certCheck struct{}

// certWarnDays is how far ahead an expiry is worth putting in a monthly report.
const certWarnDays = 45

func (certCheck) Name() string { return "certcheck" }

func (a certCheck) Parse(raw []byte, r *model.Report) error {
	var in struct {
		Certificates []struct {
			Subject       string `json:"subject"`
			Issuer        string `json:"issuer"`
			NotAfter      string `json:"not_after"`
			DaysRemaining int    `json:"days_remaining"`
			Origin        string `json:"origin"`
			Identifier    string `json:"identifier"`
			Region        string `json:"region"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("certcheck: %w", err)
	}
	for _, c := range in.Certificates {
		if c.DaysRemaining > certWarnDays {
			continue
		}
		var sev model.Severity
		var title string
		switch {
		case c.DaysRemaining <= 0:
			sev = model.SeverityCritical
			title = fmt.Sprintf("Certificate for %s has expired", c.Subject)
		case c.DaysRemaining <= 7:
			sev = model.SeverityCritical
			title = fmt.Sprintf("Certificate for %s expires in %d days", c.Subject, c.DaysRemaining)
		case c.DaysRemaining <= 14:
			sev = model.SeverityHigh
			title = fmt.Sprintf("Certificate for %s expires in %d days", c.Subject, c.DaysRemaining)
		default:
			sev = model.SeverityMedium
			title = fmt.Sprintf("Certificate for %s expires in %d days", c.Subject, c.DaysRemaining)
		}
		id := c.Identifier
		if id == "" {
			id = c.Subject
		}
		origin := c.Origin
		if origin == "" {
			origin = "tls"
		}
		r.Add(model.Finding{
			Source:         a.Name(),
			Section:        model.SectionSecurity,
			Rule:           "certificate-expiry",
			Severity:       sev,
			Title:          title,
			Detail:         fmt.Sprintf("Issued by %s, not valid after %s.", c.Issuer, c.NotAfter),
			Recommendation: "Move the certificate to an automatically renewed issuer (ACM or ACME) and alert at 30 days.",
			Resource: model.Resource{
				Provider: providerFor(origin), Account: r.Account.ID, Region: c.Region,
				Type: origin + ":certificate", ID: id, Name: c.Subject,
			},
			Evidence: compact(map[string]string{
				"not_after":      c.NotAfter,
				"days_remaining": strconv.Itoa(c.DaysRemaining),
				"issuer":         c.Issuer,
			}),
		})
	}
	return nil
}

// titleCase upper-cases the first byte. IAM principal types are ASCII
// ("role", "user", "group"), so this is deliberately not Unicode-aware.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func providerFor(origin string) string {
	switch origin {
	case "acm":
		return "aws"
	case "keyvault":
		return "azure"
	default:
		return "net"
	}
}

// compact drops empty values so the findings JSON has no noise keys.
func compact(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func itoaIfPositive(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}
