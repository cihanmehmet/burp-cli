package reporter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/joanbono/color"
)

type Evidence struct {
	Type             string                 `json:"type"`
	RequestResponse  *RequestResponse       `json:"request_response,omitempty"`
	InformationItems []string               `json:"information_items,omitempty"`
	FirstEvidence    *Evidence              `json:"first_evidence,omitempty"`
	SecondEvidence   *Evidence              `json:"second_evidence,omitempty"`
	Detail           map[string]interface{} `json:"detail,omitempty"`
}

type RequestResponse struct {
	URL      string    `json:"url"`
	Request  []Segment `json:"request,omitempty"`
	Response []Segment `json:"response,omitempty"`
}

type Segment struct {
	Type   string `json:"type"`
	Data   string `json:"data,omitempty"`
	Length int    `json:"length,omitempty"`
}

type Issue struct {
	Name                  string     `json:"name"`
	TypeIndex             int64      `json:"type_index"`
	SerialNumber          string     `json:"serial_number"`
	Origin                string     `json:"origin"`
	Path                  string     `json:"path"`
	Severity              string     `json:"severity"`
	Confidence            string     `json:"confidence"`
	Description           string     `json:"description,omitempty"`
	IssueBackground       string     `json:"issue_background,omitempty"`
	RemediationBackground string     `json:"remediation_background,omitempty"`
	Caption               string     `json:"caption,omitempty"`
	Evidence              []Evidence `json:"evidence,omitempty"`
}

type BurpItem struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Issue *Issue `json:"issue,omitempty"`
}

type ProcessedEvidence struct {
	Type             string
	URL              string
	Request          string
	Response         string
	InformationItems []string
	FirstEvidence    *ProcessedEvidence
	SecondEvidence   *ProcessedEvidence
}

type TemplateData struct {
	GeneratedAt string
	TotalIssues int
	SummaryRows []SeveritySummary
	BarRows     []BarRow
	Contents    []TOCEntry
	IssueGroups []IssueGroupTemplate
}

type SeveritySummary struct {
	Name      string
	Lower     string
	Certain   int
	Firm      int
	Tentative int
	Total     int
}

type BarRow struct {
	Name     string
	Segments []BarSegment
}

type BarSegment struct {
	Width int
	Class string
	Count int
}

type TOCEntry struct {
	Class   string
	Anchor  string
	Display string
}

type IssueGroupTemplate struct {
	Anchor             string
	Number             string
	Title              string
	Severity           string
	SeverityLower      string
	Confidence         string
	ConfidenceLower    string
	IconClass          string
	Host               string
	Path               string
	IssueDetail        template.HTML
	HasIssueDetail     bool
	IssueBackground    template.HTML
	HasIssueBackground bool
	Remediation        template.HTML
	HasRemediation     bool
	Instances          []IssueInstanceTemplate
	InstanceLinks      []InstanceLink
	HasInstanceLinks   bool
	PrevAnchor         string
	NextAnchor         string
}

type InstanceLink struct {
	Anchor  string
	Display string
}

type IssueInstanceTemplate struct {
	Anchor          string
	Number          string
	Title           string
	IconClass       string
	Severity        string
	SeverityLower   string
	Confidence      string
	ConfidenceLower string
	Host            string
	Path            string
	Detail          template.HTML
	HasDetail       bool
	Notes           []string
	EvidenceBlocks  []EvidenceBlockTemplate
	HasEvidence     bool
	PrevAnchor      string
	NextAnchor      string
}

type EvidenceBlockTemplate struct {
	URL              string
	HasURL           bool
	InformationItems []string
	HasInformation   bool
	Request          template.HTML
	HasRequest       bool
	RequestTitle     string
	Response         template.HTML
	HasResponse      bool
	ResponseTitle    string
}

type groupedIssue struct {
	Item  BurpItem
	Issue Issue
}

type issueGroupAggregation struct {
	Name       string
	Issues     []groupedIssue
	FirstIndex int
	Severity   string
}

const reportTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Burp Scanner Report</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none';img-src 'self' data:;style-src 'unsafe-inline'" />
<style type="text/css">
body { background: #dedede; font-family: 'Droid sans', Helvetica, Arial, sans-serif; color: #404042; -webkit-font-smoothing: antialiased; }
#container { width: 960px; padding: 0 10px; margin: 20px auto; background-color: #ffffff; }
table { font-family: Arial, sans-serif; }
a:link, a:visited { color: #ff6633; text-decoration: none; transform: 0.3s; }
a:hover, a:active { color: #e24920; text-decoration: underline; }
h1 { font-size: 1.6em; line-height: 1.4em; font-weight: normal; color: #404042; }
h2 { font-size: 1.3em; line-height: 1.2em; padding: 0; margin: 0.8em 0 0.3em 0; font-weight: normal; color: #404042;}
h4 { font-size: 1.0em; line-height: 1.2em; padding: 0; margin: 0.8em 0 0.3em 0; font-weight: bold; color: #404042;}
.rule { height: 0px; border-top: 1px solid #404042; padding: 0; margin: 20px -15px 0 -15px; }
.title { color: #ffffff; background: #1e517e; margin: 0 -15px 10px -15px; overflow: hidden; }
.title h1 { color: #ffffff; padding: 10px 15px; margin: 0; font-size: 1.8em; }
.title img { float: right; display: inline; padding: 1px; }
.heading { background: #404042; margin: 0 -15px 10px -15px; padding: 0; display: inline-block; overflow: hidden; }
.heading img { float: right; display: inline; margin: 8px 10px 0 10px; padding: 0; }
.code { font-family: 'Courier New', Courier, monospace; }
table.overview_table { border: 2px solid #e6e6e6; margin: 0; padding: 5px;}
table.overview_table td.info { padding: 5px; background: #dedede; text-align: right; border-top: 2px solid #ffffff; border-right: 2px solid #ffffff; }
table.overview_table td.info_end { padding: 5px; background: #dedede; text-align: right; border-top: 2px solid #ffffff; }
table.overview_table td.colour_holder { padding: 0px; border-top: 2px solid #ffffff; border-right: 2px solid #ffffff; }
table.overview_table td.colour_holder_end { padding: 0px; border-top: 2px solid #ffffff; }
table.overview_table td.label { padding: 5px; font-weight: bold; }
table.summary_table td { padding: 5px; background: #dedede; text-align: left; border-top: 2px solid #ffffff; border-right: 2px solid #ffffff; }
table.summary_table td.icon { background: #404042; }
.colour_block { padding: 5px; text-align: right; display: block; font-weight: bold; }
.high_certain { border: 2px solid #f32a4c; color: #ffffff; background: #f32a4c; }
.high_firm { border: 2px solid #f997a7; background: #f997a7; }
.high_tentative { border: 2px solid #fddadf; background: #fddadf; }
.medium_certain { border: 2px solid #ff6633; color: #ffffff; background: #ff6633; }
.medium_firm { border: 2px solid #ffb299; background: #ffb299; }
.medium_tentative { border: 2px solid #ffd9cc; background: #ffd9cc; }
.low_certain { border: 2px solid #0094ff; color: #ffffff; background: #0094ff; }
.low_firm { border: 2px solid #7fc9ff; background: #7fc9ff; }
.low_tentative { border: 2px solid #bfe4ff; background: #bfe4ff; }
.info_certain { border: 2px solid #7e8993; color: #ffffff; background: #7e8993; }
.info_firm { border: 2px solid #b9ced2; background: #b9ced2; }
.info_tentative { border: 2px solid #dae9ef; background: #dae9ef; }
.false_positive_certain { border: 2px solid #3ba317; color: #ffffff; background: #3ba317; }
.false_positive_firm { border: 2px solid #7dc164; background: #7dc164; }
.false_positive_tentative { border: 2px solid #b8dcaa; background: #b8dcaa; }
.row_total { border: 1px solid #dedede; background: #fff; }
.grad_mark { padding: 4px; border-left: 1px solid #404042; display: inline-block; }
.bar-row { display: flex; align-items: center; gap: 0; }
.bar-segment { height: 16px; display: inline-block; }
.bar-segment.high.certain { background: #f32a4c; }
.bar-segment.high.firm { background: #f997a7; }
.bar-segment.high.tentative { background: #fddadf; }
.bar-segment.medium.certain { background: #ff6633; }
.bar-segment.medium.firm { background: #ffb299; }
.bar-segment.medium.tentative { background: #ffd9cc; }
.bar-segment.low.certain { background: #0094ff; }
.bar-segment.low.firm { background: #7fc9ff; }
.bar-segment.low.tentative { background: #bfe4ff; }
.bar-segment.info.certain { background: #7e8993; }
.bar-segment.info.firm { background: #b9ced2; }
.bar-segment.info.tentative { background: #dae9ef; }
.bar-segment.false_positive.certain { background: #3ba317; }
.bar-segment.false_positive.firm { background: #7dc164; }
.bar-segment.false_positive.tentative { background: #b8dcaa; }
.TOCH0 { font-size: 1.0em; font-weight: bold; word-wrap: break-word; }
.TOCH1 { font-size: 0.8em; text-indent: -20px; padding-left: 50px; margin: 0; word-wrap: break-word; }
.TOCH2 { font-size: 0.8em; text-indent: -20px; padding-left: 70px; margin: 0; word-wrap: break-word; }
.BODH0 { font-size: 1.6em; line-height: 1.2em; font-weight: normal; padding: 10px 15px; margin: 0 -15px 10px -15px; display: inline-block; color: #ffffff; background-color: #1e517e; width: 100%; word-wrap: break-word; }
.BODH0 a:link, .BODH0 a:visited, .BODH0 a:hover, .BODH0 a:active { color: #ffffff; text-decoration: none; }
.BODH1 { font-size: 1.3em; line-height: 1.2em; font-weight: normal; padding: 13px 15px; margin: 0 -15px 0 -15px; display: inline-block; width: 100%; word-wrap: break-word; }
.BODH1 a:link, .BODH1 a:visited, .BODH1 a:hover, .BODH1 a:active { color: #404042; text-decoration: none; }
.BODH2 { font-size: 1.0em; font-weight: bold; line-height: 2.0em; width: 100%; word-wrap: break-word; }
.PREVNEXT { font-size: 0.7em; font-weight: bold; color: #ffffff; padding: 3px 10px; border-radius: 10px;}
.PREVNEXT:link, .PREVNEXT:visited { color: #ff6633 !important; background: #ffffff !important; border: 1px solid #ff6633 !important; text-decoration: none; }
.PREVNEXT:hover, .PREVNEXT:active { color: #fff !important; background: #e24920 !important; border: 1px solid #e24920 !important; text-decoration: none; }
.TEXT { font-size: 0.8em; padding: 0; margin: 0; word-wrap: break-word; }
TD { font-size: 0.8em; }
.HIGHLIGHT { background-color: #fcf446; }
.rr_div { position: relative; border: 2px solid #1e517e; width: 100%; max-width: 100%; word-wrap: break-word; -ms-word-wrap: break-word; margin: 0.8em 0; font-size: 0.8em; max-height: 300px; overflow: auto; padding: 16px 20px 20px 20px; background-color: #ffffff; border-radius: 4px; box-sizing: border-box; }
.rr_div .copy-btn { position: absolute; top: 8px; right: 12px; background: #1e517e; color: #ffffff; border: none; padding: 6px 12px; font-size: 0.75em; border-radius: 4px; cursor: pointer; transition: background 0.2s ease; }
.rr_div .copy-btn:hover { background: #163b5b; }
.rr_div .copy-btn.copied { background: #2d865d; }
.code-block { margin: 0; padding: 0; font-family: 'Courier New', Courier, monospace; font-size: 0.95em; color: #1e1e1e; white-space: pre-wrap; word-break: break-word; background: transparent; }
.code-block .HIGHLIGHT { background-color: #fcf446; color: #000000; }

div.scan_issue_false_positive_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,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)}
div.scan_issue_high_certain_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABLNJREFUeNrEV01sVVUQ/ubc+376Z1sQKBSI1WjVNBW00cQEo3FhSFSqG0z8iybGBd0YF0IIO0uUBTGx0Y2BBHcu3BITIYSFuLAEQ4pEMKiPn6qQUgptX+89Z/zOebUS+t7rfS7stOfde8/PzJw535yZEb1nEAvkBGnOoVxwMHwH/+PU9ymHtFsctqpgC6B9Cqzniqb5lTOcWoLijECOsx2GkUv8hqrC/3leaXkaLkkgxiyIjFGHxOsU6aMO+h6ZbKdOuX/676A2iljNgcc473WKTYyar9i/n+1kPRmmtnCJrOiniXGjVOA1biIn1YVXI9rRvco2quTB7yibAtyG8WYTPGiNG6PgIWQXWpVokSHyG4PIQ6rOn8kdCmhFMFxFnTTWAS76ka23pmCRwEgnbkAnb1Y0lHpqai/bqSjKDRAAUMetaaXxqCjb+F0Lkrzrmc3bE6LI1z40Tk5SuIvjMOvXwKzqhPt9vLKLOkoQjHlTaDoRF4o9xsSI4wKiqABTLpBfQVAmnss5e4zorwtMWAv98xqKu95Fy9GDaP72IPJvvAgtjS99HM7GJl84FsU5vmswnIlS/qTeAnaErrZxSSZXriJ6cjPyu94BWlsgK9tRHNkD07MhHEkG2kiLj9Cxg3saohQ2cvem4nbwY+ldTE9DeroXw8L33ZpZej3PPcoXd5g4d1/AwFzeA88NZ0Z6RI+aKS/uL89xzGTzDO8NkRmm/YMbdrDnFfyfRA8SE2+P88UOI6rbsBwUTK6DHgPPyjLJJwif8UfQp8uggFZuxD5eS7oWy0Vi1nkLtC2bAtA2Mx8JspOlCxULi/sL9GfnGlbBEA1TDVmtuQj99dKifneBfc1Njcq/QQzI5YYUWLsK9rtTmPvoC+jULei165gd+hB6oQTpvKtBN8RlmXr4hQMCfSvzOfhoOJfAXfkLUW8Pr9EU9pcSzMauClfVBtwQB304PtIQCPw5NzGMrl6B9IeTSE+NwaxbVbmiNTsnH/4ZHY/IZP+2VmPtpA9MWWNBiHo2Rbz1qZAbpIePQ9pagZamRoDo1NqOmHr4lOZLPt/MpP/MbDB704FhKrAldCUHvsbs+/sg+VymgMR8019Eh1TMlPEa8zrek9V4PhOKn396QXjIQN9+mTnCppCoNBCP9gRIWe/aIiWmAvskixa5XNXEQyfpzbk40+6duo+tJhdVLc/dmAAIJksf8Hl2qcBkutfAHv0ec58cCt6g0zMo79wPd/pnyN2d9YVLMP1Zm5R3KjHkm0xsfmkelT41s11RYs9xZmtdN2TyoX9chelnsptauLHzECaoYaymJ4St3Uxdcj+j4LjMXwQmLPAJgn8YjDvIExy6XtcNCzkILeHO/QbHW1E2dC0hPIifIOwfv1141cKEQ2coop8vo3UcKKTgsrIDsqJ9AVU1awhg1Dn7CKf8JHeUObV8pkTfGCDXvf891FYKOfr6XmfTAQovVSuxTP2yCrsJml6a7XN+TmQSGqomTLD6+cy59AHedrtRp3CSiU2D/y52FtGcq1zpoqFOdPOmZUndTsbPcWgLx/v53h0S2goRM74cd6c5dpy1/DdOk0lfhkkozz1746v/SkZ8G/0twAAD7yPRry7F6AAAAABJRU5ErkJggg==)}
div.scan_issue_high_firm_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABEdJREFUeNrEV91vVEUU/83cu11326XdLR+tqNgEwQgCCcXEVI0YjQkvalZMxFf4A/wDpAkhPJZnNLE+a+K3PogRRVJNTCCmATGaCEEQLWW/u93dO3f4zdytW2x7996QuCc5d+bOnfMxc35z5lyhp6fxLwkNNJOAJwHpmQH2Hfa16Y8B+gA7z0DjMbYPkJ22pCL/yemX2H7HuV9S1xX4Row6oINZPgeazfZYQC66kcCTlH+TSg52mTnEeTvZvtY2+AFlT7L9IUxIhlhOQYu3qWyGLwcRlzRlNIzsO+RUXAd2Q8mL8MUR3CtpfZiOXLI6V3XAxH05az3B2F3gt7EQpUGb5sL603ePrU4PM+7nyU/Z8OgOSzQIuiVeTG7jys/xiwg1bkCUHYQqVdCav83oDxJNTrgTvuZui+/hJrZbeSktu1BOB26+/jbYiTBQCmvwxsxPuPD+J/CVh10vHcCW554GypVuO0FH3TNw3M20oe8OAfQptqNdY5pOo/XPLRr/GPVSGV6jifPs165cAzKZKOA0Nk7ZI0mW7cFt9Dwa4PpcNApFu9D+3BBSQ+vsrtQLBfstIh1p26QDdvE4ERnVvoZwXTgJF5p9ww7fJdl8i0QWA+KEmS+J+Cw9yOP/JIsTkYcjc8QAXkGvSDovGwf298wBiP3EgN7ROwf0DnMKRntnX48aBzK92wFkZOeyRuQjpD0PqtWCYCo1rFoefLJNrzH3wGSOMnkgsggNJ9fn7NmvzM2xTcDt60P/hvUsNhpxHSgbl6/HEqnVkRjOYe/reQyOjiDNS2n8jTxSD22mumpcB6673NJZgmFfnEoDxSI27t2NF7eOQSsFMcxcVix3bsroNGtS8em4GLAp19x8949AbHkQqNRYO3pxjZv5p5nQ1WdEklpWYHZPo/exdmDcb537EarZwqY9O801CywsxACi8KjrU5egqrFImIbjHO56lxty6Gcqhcsffo6fP/qCIhqPPv8s9hAHxim7E1F2Uan3OHdB2ntZeUcjGTc0MID6H1fxy1dnkM5lLRB//eYsbl+8zEJlXfTt99UkH7wNjddS/sWh45Fi6CtIFiUJhqFRrWKxUrXHMDHQz9WrqKs/zoXfYOhNPdBeudd6i/3Zrk5Ua0iObMT4oVdZkGStI+OH8sjwRKBU7m7c2AhsWTwJPfVu53hJZxh9yd/4kl0zJMuKUj1fsFnQ3bQhOBU8kmsuIBgvMllt5ernl+ZJ27EsYT80G0/QylyoIuNEoQTBktylIyiVuhvX1Nls7FtufOWPiT3j/u9UtotvM6Fbaai+yKNXD26TcOMzVqfR/Z95clUBgZsUmKDgpMn+93DbtWh0ksCdYP/mak6GZw3tH+PzEa5wiu3fMQybuVOBrNWx9mbqk9MrR1nxBj9HFphB6pXmB1O8wEH+geBxMnMwBtsSBAGumdxOmbNsv+bc+tKxXcI4880KU3cEGADDcbVpFKB7lwAAAABJRU5ErkJggg==)}
div.scan_issue_high_tentative_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,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)}
div.scan_issue_info_certain_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABElJREFUeNrEV81vVFUU/5373nw405npgKVpY9QU4qof0cSgMZEFC+tCGiMxKnFT2ciqgBujCRvdAfUfMGFFYoyJbJRgABlicEEw7TQxoi0tFkpEWjpSmM93/d0704+0nXnvKYH7evvuffPu+Z17zu+dc66MHDkC0zQvh5erYxx5EDFP7b/Gr7pDIIOcvAotfbx3sWcbLyywz/G9vIjk+PJpDdyGogTdWK3NWKGqSqjxkoZsF/6tl0tHRMs7HCebvJNif5rv7STQfo6XKP8r3kfZJ1oJV81+0PV/R9nz7B+0AN+sJblmmIbMU86x/6CA9HDH4xwcxv9tGofosjxH2wMoYPc9QO8Y8D4/2cViCQ+KxbrK0tqN9Pk43TKg6xirCmisXpw+RTk/tzI3SWb7/MJdxOMxJBMJ3JlfgOdp+7xFSxjZQgysUcKNILpGG+cCb3G/nRvAl198AW++8Rocx8GZcxfZc8i2Z/yWxl0duUBLbDdKGHWVi+UrcpzznvUmWt/u3VtCV+c2DL//tgVMp9qwd+h1PLejBwt3F33oYEClx9HuqNYC01XNfvX6WU97B4NwqlytEji94fmTW7MolysBOGmVGOGGn3EQWSHhZ0FJbXb82x/XcPmX8ZVnk9eu48rYBLZkM4FkmCBEunzOTcOlBmkGj/eCKhChz2OxKE6c/Aa/Xp20HLh8ZYwk9BAjIc09iBX4t0+Ud8BEwqE1Mde3edQ2mXgCJZr7+x9+pB89dG7roGVSqNVqgcND3Qoy5NIju+FDvA074OuFwj8kYweUUpZ8sWjUfoZah5Dlqd0usXvDgBuQv+/M4/mBXuzdM0gXuDhzPodzuUvYmm0PESAtGfvoAt0dRoH79x8gS6APh/etBJ5339qD6ZlZzPx5A5l0Koy4bvMVpMOsKJbK1vTro153VydDczFspkipsCuUEpKtujE+kJSGD6HlsRdCJziNh9UKpmaZw2Np1oU3FcNxXh4TPLEnqIBzNmwceDjNlgBnlQd1StvS8VHDgzFUTinxKoaEJ+VRe5+YjtYFZSa0wic6YDowodZ1NxbTkYhrq6KAuzf9U/sZeqJQE5nRokclABciBN+s8FhcLFglguyemF+URaYrxFbLkFW4h2iFKT87JJMJzN36C19/+91K6j1/8ZJNzdlMxjcDEm+qgspBg2hRPdaEdTeIyTS7orr8OwfxVsmonaWYqQGvsjBxHIWp6etoa0vCcZ2m9UBjY6WKVHYBldWT0bLZ61M1y4z+EqPTT80qY8MBhyF3CxPSjZtzdp7JpO0zn2JkieXfKx682Tq4ND0XjHmCft6bBqjlnJ9ieZZm9lMt6gCpS83XRA8Y2bKO7GpzlsoUidnv+RyrAtUcwHFPdD+VmAx1Nmws/kjXT0hf2gNniLLBrOHaXka7w60irRvgszGn2/1U5mNaelDs8RxNj+eEyhH0NE19m1U//M4Z/wowAOHbmDGmtG2lAAAAAElFTkSuQmCC)}
div.scan_issue_info_firm_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABKFJREFUeNrEV0toXFUY/v5z78x0JjHpJGPbJLVVFFppTdzUKopWobEKFUnpQkHwsXElIiii4ErwgZCFaE1du2hdiIguIqaLFtRN0mgwtEUMtuo0mTzmmWQe5/idM2lDNXNzp0pzwsk99869//M73/8f+WJsDHYYTsUZ18L/As0nWgmMMfB4LyLb+cPjXD3Eh3u5voXTR31ozj/52iRXp43ga2hzQWr2DcrQlCXayS9TfNWjBlP/8IqAhkNB7uZ8hR88Zdz7ptGr7fzpThoxIIJBWvwVPDPIZ6eC5a8xnApaqowM+pAxLp8xIYy9RoDgMDwZ4fUzzmRTBvCD2xXUBCP1skGAz+EMeVqUTDJ1969pwBUFelVRL0M+zuuehoqJC4uNTfEEEq2tFh/uPmBs9ZQ6QyMe++dbyl8BQoTqGe4uiPqety2NdRtn6ObOFJYWS5ibnkZ7RwcikQi01sHBUOobOrfPOS316UevRp1/Ro0YSMIEBN3ukc2pFMZ//AEnj3+CxWIR/UeO4uDAEdRyOSJeB2YlKmpEKrWt9KMk9RQwfE6s9zavu9fLeLylBQuZDE4MHUP60kVUq1V8/ukQJkdHkezsDAEJaY2IssB0EVCoq+/i5c0wcFOej1Kp5DxvbWtzs1IpI59dgOdHQuCSOjz1pCey3wJQMewMvbwVFtilYh7dO3a4sBeyOfwx9Rse6D+EvnvvQ3Z2NpQMG3NP1PvWcxkeHY8xBlk+j4XaWUxeJBpFPJHAL2OjKDLvvVTueZ5bK17DDrLtbb4WOUSWi4X9yG658vIyasz9vgcPIBqLOSwUqNxrQrnUZR0lU+OR6+GYtmQSmctpLBEPqW1dzqBqpWK3WjNEdcDnv7uaIjemIMltOHl2zG3DUqGAR4mHhw8/QSBm1yOka3YE0bfHmtvTjAGb4nEUqdRuvanz55wBJ44fw4WJCRJSZ5NMbVIqiPXWGj4BuDAzg+XFJWzp6kY7977N/Uz6L4Iz0nQqVbO1xjKd5/sOfJZ67b1PGl6PihsaQBAW8H8Mkeuqlyz5uIiNGgZpy4bjG6FbnPv4WXkwwxsWAGNGWAvkO66zN1y5rQMaJ8lbWntiPrrR8Tc18yUqelq5/tiYd01osIuj3Uq5DEXzLfXansCWZBWahmlBzbxmSVNpY3shk2cUXqo3JsHDKrfk40d8ZKYvsyRnnTEdqZtZC6rhtmtND7EUnhdP2BOKrc22J9QfKpjTWMcI2wfe1N6OgedewLae7S4iA88+j129fcjOzYaAvvldV/SLrres0eVTKycj2yQwGvEyvHNSP/U0LEZ2JNmUzmdm2KAU0b3zVhTzOVemg9JAueVlo3dVxEypf58LLCyxKMbcw8VUEAasI/OzGcTZkm/p7kFufu4qJoKaKXq4n+Q9pdk2aFWfa32Rpp+9vH4blEdriO0FrOc2KhJMxT8Zo63Ms64RMauzgckmT/v6mZZXeVP8b2SD93g47WOGfw1/NFv9/AOaeQdj/g5vLjWhd5bOfczI7CbUXg8s7yGEpSnkDRrDzlkOuuO5yF66ttOeUVacyDkDBRP09Ax/H9bQeRWCXP4WYACYVfKTOSe0SAAAAABJRU5ErkJggg==)}
div.scan_issue_info_tentative_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,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)}
div.scan_issue_low_certain_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABGFJREFUeNrEV19oHEUc/mZ29y5J0/SSS1WaqFgtlBZqKDbQF9tCS7BPtgjqgyKSZ6GKD1owFEoVQSoIvhaUvojgY1NKiaANSsF/ldZGtBaurVWTXE57//Z2pt9v73psQrK3m4L5HcPtzs7M9/3+zfxG5Sa+R1TqyMBAtd8byuGbhYbdGEAfZNfTfN1hgWE+r2sNq3FGgQN/sRZfaWXPsO+arONwoOFPRHGVAFW+BeGbiIsYadHYyoXeMFa9GAFcKuuJM0hiI3x+gWNl8ud8Psk2HYehY4DJU5+gRle48HgM+PJi8RzbBRI7xbc+6UhEQIVz1ZAP52ID+i3cp9D4r9CBlwk12pEA/SzgT9Th/Ei+T6kVWIcKkmlQDRCU2WzEbMvLENf9lv9jSy2hBUSaQ4M34A5U4V5kf151CA4z5yPb46K/3wOKPgKf6+hOXtGThNwZJaEJKsDw4aGMzHkuk+uoOcGf2bkBvx95DH+8vhnHnn0IoCVM0ImAKNs1xdzoCp0jlGrIhql3B91HGXQjupUyK/q0YtDd5+GLl4axab2LvqzGO/vy2L2tF2be7xiZNF+fRvY0SdDlbCbMSruRH4/rGM3b4hsM5j1kl5h7y0Am/JYoLOEcdpEddWl5xkC4zbydOKzFBQ0LP1hMtiLgWqXIDvV+QxKdBFxOG7/fdLOpR6s9UN6j2igcIPde/O8ittfPa8blfoU1Emv3SijtWCN0scJ2Br4dwtrJoFigN733kvUlSQa9Gstp5o3nLIbs9riUsal1EQKlVFMI9M+sj9qSPWdmth5+Ww2BQpoZulujUvJx6NMCbv7bQIlMjk3N4psr/0HLwZRO/nKh1E8MxLHElGllZ8DDme8WsPl6haZXKP5ZY8nBbdWhh0yKSFLmkrZWn0ttN3F/zkOtUEHx1zuslRy4GZ0CvL0PTNEF9jwfF9KAG579KDWwezSHsb35MDAbdEeas0AmBQqf6bBohfo46W5uONoQ/OjBBzA9/ggmXx7GOf5nmRWmZtLk8lmtnBuyFZOBfk8lzGTDwiO/qQvHDwy2+/Y/3oPDu3Kwc/Xk+iu8GZ7DTWBV4uMRlcQKnOEvo+l8mS5wVNJN7BNrzSXDoKEFAvGGXBU+pDWmO+L3aJSY84dO38BcJUCddcHJ6XlM/lCCHvASeF7dJtarliaQpjDxW+R4NFw+mJEqtmNRwrpww4NZrMso3CxUmQmsb7KSCTZGd0t3N7ZyxNV7vbwZOdEBZSb6LjpISuiHYy3BTWeB1fCCeIM1ohPuAXHgijWTv8+iejV6cuhm9NtoTXOLlpEj+su480CWcHocOL1sOq4kCsFmWHmOUP8LzauIareVNu8iFSNbSK1YW23F02zmI8bYNjK8vNyZqTscfO+ybeHjB2y3U6CXCXyqqbV9Lbxmrkhz4lokCKVK9Zt3JRvRQ0nwqC6OGOOXPRzwZCtG+ltKFDnwFqf8zO9fE/QsF/g7nBVewG3LycJj8d3hrgADAKAAqH3WrJ+hAAAAAElFTkSuQmCC)}
div.scan_issue_low_firm_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABBdJREFUeNrEV11oVFcQ/u7Z3Wx+NtmYTeJPICWhNJIY81D8ebA0D6WI1raUQvJSKKUPpVootQZKsUEfihAxD6KoUNqnJlgQClFRqBHRtg+lGn/6h4otjRiTqLubbJK9u/f2m3M3mhi4P1rMwNwzd/ecO9/MmTMzx+j+ycY8kldV4FmZZAB1fN9k22jnawu5nhyes+o25/zG8TznnKD85+wfslgEm6NhzVcXhje1cfF2frSTcsRlXgV1rOT4FhXu4zjAdTIOun1ceSjvhYVL/NA7HsoXEMG8RovPEEwfDU8EBdBAvkz+GE9PnQTzO/klvRWeAAzur4EhmtDqZh63BMVlQGkFlxjOuwvVcM45Ttv8MGIKrB5TvpS//Eyp3FU5h3g1kEnnMTacRHkV96eIv1ue+zJAHet05EUcDj8G4AyfMS+fxmuAaxcu4vv9ezA9mUZ753to73gb+bwPEErHRS1ja1K2RM1RvovPZi/l0VJg4r6JgcO9GB++BcuycPxIL24MXUdFwld0liKPPu1G6xGAGgL4wk9Ehenq5NgEcmYW8aV1KFuSQJj+T94d4egzLBW2UN96RzT0c6fv40XUobDinkcpW5pDkQiBFdEb/s8oqUfMV4xOwf0+njUZ2CDHXTzwKoWSZw7A8UKHAHgFi0G2LhHtiglk1aIAcJJXiyKSOiweVSnXrOexgf8DWSro1yTv53OAOTMNQynNkhPMbBZKBd8IWZIMsiJnAktqY4iWxJC8/TdSo3dgMQcnlq9ALhvcBZIH/g2yYDojFTCM17dux7KmVsqVeHPbZ2hobUBqPKD5Bu6GC6V3Y4DgxYNR4IUXm/Fh7zfITpmoWh5B+j43NF/wqX+6olgQTgc9PkLpe2xzVrAxbI6wLEtMBFYu0feDAJASfM/3GoZsJAqUxYGhwT9wtv9HjSlW6XggIICjyo5oqw74DhpaGaPyc98dw5FP38W33dtwdO9uBqeJaFkgR57g445CSPfGPU519iYGP0b+yWCw/2uUMACrG5swdPIYrp7/BfFEIPu7nEKc06rTRPORn4wgXU9xaQjFdMNU6gEmyWBpjsUrkDd9K/+KZf2aZc32A05ncJDyoOcxnJR+MIo3tu5AdX0jQqEQNn/Qhaa1LWxUfCkfpsEPy7/RfdF+1B/nUQQTf1F6zk9TKudeesLa+nJkUkB2Bl7Z0OTileSbC9tyW0dGlujWUL7hFj3itNSY0x9WLSvXR5LZ2Ev5lG7D5ihfeC9wevVRchsnn3LNBeSZDHQOkKNpGO4Jh/NXc/zV782IO62z4yfkiaeseHLCRPn1J7sb2niexn1JOUjNYGLGIXpF2vwut9Pl53Y8Qv6cILo5Svv2Mi+drfyoBGplwYiUIQANXKV8gSzpPeXnWP8nwABTjkvuiAutxAAAAABJRU5ErkJggg==)}
div.scan_issue_low_tentative_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,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)}
div.scan_issue_medium_certain_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABDdJREFUeNrEV01sVUUU/mbea62lf4/+GPoXF5AgAW3qb2JiCWrQhSGxIairYiRuCJAYEuzW4E8MiQRJ2LGoWxfKAknTdCE1oImNFoU0RgyIkJafIqXlvXfvjN+ZeS2lr+++e4tJTzK5d+6dmfOdOd85c0bZfZsxL0oBuZxvKQ1o9k3A73yHboYJXwdsD6x9kh/a2VYVZmbZ/ubAC/z/PcefZP8irJF5/CRDrF8/CIEw9O+UNKLEDVLrqfgD2PDtBQoXSy1bE5V08fmWV6y+ZvuCL6ejVOjSiikm/BihOU+L34tQXkJsr9sN2ONQqEsAwClvQxj8xPah7yosX2wfLTnPl+e9KxYDEGvnm/jLrIUNfoGyz5RWXBg/cweYnoLbchUJspXrneG0rQ6EjLfWNY0s+eMaiXdvdjWC7I8c0hipXMg5Sc7VNgDNbcCNq0Cea+hU9GYo8x1SqhsVlWRf2rW0Y+ScmPwQ189EWiO/Ji4DL24D3v0IqKoGBr8CBg4CDelCxJTyhpXoGobVa7gTMxIZen7rYfq5eFdZf8u2N7QAe77ks5kAyM033ge6twDXr5Thg6xt6xhRA85wNk1/81u+iX45GItsuVmgpcNv4UJp6eS/bAxOOhxv0hXPicu0U2rRj6UouqQRnBIQdBgsAnavPAcWboTC556ESpKR3ZUs1CweSnxmfImkfJwusK+yV4OVEKV2SOC/gpUShR7hwCasnGwUF7StIIBGvTz/q/8LgNGJKW2Yx9MVzGiL8sAjj8rpmdgSATCdaIoomrhUnAeu/QVUVi0DgMLlRFOqWXtMTQCHd/M5yQPsLvDtMWB0mCVJa1IAk2k64Fe+vJYoiUgqHvkG+GPUW31pHMjwXEhVJHXDmIaxg8nTGEnYSGv/PMclRoC6jD+Ukih35xKGld3VrXm+32SnPmb24tnP2uHfm8DTL3vFPw95TtQ3FXMjSgLTznqA5YnFUZ5O/bHiQaJAOPDOAaB3r//2+xngs53+qBaSxpNT1HlFEwBR209jx/b0LaBz/X3lIhteAHq2+yopvuyX3dREIb64QxD7XKlVTjTjf3Z6aWCSH+K40NgBZMMx5KQgMb445IXhMN9Hym5ETb239Mge4O5t7l7el2Q/nGB92B6DeHaCvt85/8n2dd0nt0Y1KlLjriyPvKzAg2hbR58zDC8yGmpXR0fCnGE58wQNvTDXfzCfGlcoPsvRZ9nrKFlYCgix9sY/XmHmsegc4JUFyJvNC5UXX0z8j6vu7scYjaxupdWwLK9r9KWYu46VjPdxBLy2hcUuLlFDqymG2xYq6S9cPJd/YBoc4fVuA1H8thS/dHTM208IYh0nHpLjJoH6GSo+zvldnE+2qpIp8kESCsJKqdKUTzgOovIwDarc1Qqqh72nChzJFIyYKgAc4zqnqfQUn5NuUXfFLygIizPdfwIMAOlvjp3T7A5HAAAAAElFTkSuQmCC)}
div.scan_issue_medium_firm_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABFZJREFUeNrEV1toHFUY/s6ZySbd3VyaJqsmYKK0YFtL+yASFOyDIqLV1/oSFfRJfLBapC+ioOhDVBQU9UHQh6qvlqp4aW1BkBI1WmprL9KSXknapHtJstmdmeP3n9ndbMHd2Uml+eHfM2d2zvm/89+PMhMTsGQUoAzQUeSEz4ED6ADwdfi/Ywb5+zA/3MrxTvKtZBeV1eQL5KPknzn9huNxVMnuXZ0EqCfVFIDMjdrM8UVo8zjFtKF12kt+lxvsawZAR2zyDrXwBwGMxhQutI38IyV/ybGv0UeNAAzzxIcpeAeun7bz9Mc43lenhjoAATFU2VirbIBSf3KyqeGWxoScTAPpbi7R4bwxiQYOkh+pGL7GGokSLLcvAm1ehm8P8ZOupsKFejMwhRy8S2eBnl6uTfAQQYQyzF76wwg8+q7vWHat8Nr/ej85jWaHUaHw/PhBnPl0DP58AQOPjiLz2JME4DcHYS2g91HbN5ELoQZqJnBepfCNkRbtSMFkZzC5+z0UL07CUODk5+9j/uhvwOr+CAUIiCAJ1//ChjhZV1TKleqVllyKqvZnphF4ZbT3D8Dt7oVKJFCamWJWcKPXhyG5jeYegesRgOOIWl5u2acNkTsuNIHI6UXlym2z82gfqDeFegu+Kxqw8f00biSF0XYvH24nAPUgZ0nccDKSyLdr6uB+rAhZNWwVE2xaGQBKcspGiYJBrBytkVqQWp76zP8BwBb7eDtJ3vd9BKUSH7XloFzinKlc69h24ApViLWkvAin72Y4HUkUWQdsAiKg9gwtWS4tA4DC2VhLFuah0l0YeuIFpNdugJvqwvBTO7Hqji3A7OW4AKaUOTH+Jrxg13+U6sb2D8hrWDjzWZgiAcnps1eogXI8MxjsoQGD72OHj4C4SoEUrNYxiudywHJ8QGG/Msd+kVpwRYpsa6hNWPtTnZg/fAjl3Cy672Kzw3qA/FVu5cSJplvYkHChoz9oORbklF09mP56N/56/Vn8/fZOnP7oNRhxwFWxIvpbquASndARAGNUR2uljCcPzp/Bha8+g5vuRHJoHaYO7EFu/EB0P3AtvRT2hAwr+F6eT8+1ljp82wu6ZC/PliyXteXY7ewB2CO0SJ/Qk49Ii67thrLQ9z6kfX+KDsMC9Oo+DEnoDbJ5dh0Mjz6P1JZ7AMkJ0XSegp9Zupic+rXeuxMo+8fpD8MNw7LWlPbbuJee0Bm8LXTA6EjgSc168j9Lbbm0UcLijK7L/BrczQ9ONQ6dyi2HbZk4nZMZYEheDrNgc+ELXDhSLzwEUO3xpZ0KTzfNSwnTmvquaS4QIAtzAFtzu041zWS0NzaTf2/tZmQwx38eohy5GRVwfTRGlp7jZJyrWZV4ucRa8hvkczGEzhL8xwh4yzIMN9U4yShzemLJtqLKxWJYoCWjVc0TeqTL9w/wkddzxROZIb7rqRwiz/fn2F8eCa/n+IHfZmu1Q5uwHbf7+NcA+FeAAQAQU5ubLuZZqwAAAABJRU5ErkJggg==)}
div.scan_issue_medium_tentative_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,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)}

@media print {
	body { width: 100%; color: #000000; position: relative; }
	#container { width: 98%; padding: 0; margin: 0; }
	h1 { color: #000000; }
	h2 { color: #000000;}
	.rule { margin: 20px 0 0 0; }
	.title { color: #000000; margin: 0 0 10px 0; padding: 10px 0; }
	.title h1 { color: #000000; }
	.title img { margin: -3px 0; }
	.heading { margin: 0 0 10px 0; }
	.BODH0 { color: #000000; }
	.BODH1 { color: #000000; }
	.PREVNEXT { visibility: hidden; display: none; }
	.rr_div { width: 98%; margin: 0.8em auto; max-height: none !important; overflow: hidden; }
}

</style>
</head>
<body>
<div id="container">
<div class="title"><img src="data:image/png;base64,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" width="184" height="58"><h1>Burp Scanner Report</h1></div>
<p class="TEXT"><b>Report generated:</b> {{.GeneratedAt}}</p>
<p class="TEXT"><b>Total issues identified:</b> {{.TotalIssues}}</p>
<h1>Summary</h1>
<span class="TEXT">The table below shows the numbers of issues identified in different categories. Issues are classified according to severity as High, Medium, Low, Information or False Positive. Issues are also classified according to confidence as Certain, Firm or Tentative.</span><br><br>
<table cellpadding="0" cellspacing="0" class="overview_table">
	<tr>
		<td width="70">&nbsp;</td>
		<td width="100">&nbsp;</td>
		<td colspan="4" height="40" align="center" class="label">Confidence</td>
	</tr>
	<tr>
		<td width="70">&nbsp;</td>
		<td width="90">&nbsp;</td>
		<td width="82" height="30" class="info">Certain</td>
		<td width="82" height="30" class="info">Firm</td>
		<td width="82" height="30" class="info">Tentative</td>
		<td width="82" height="30" class="info_end">Total</td>
	</tr>
	{{range .SummaryRows}}
	<tr>
		<td class="info" height="30">{{.Name}}</td>
		<td class="colour_holder"><span class="colour_block {{.Lower}}_certain">{{.Certain}}</span></td>
		<td class="colour_holder"><span class="colour_block {{.Lower}}_firm">{{.Firm}}</span></td>
		<td class="colour_holder"><span class="colour_block {{.Lower}}_tentative">{{.Tentative}}</span></td>
		<td class="colour_holder_end"><span class="colour_block row_total">{{.Total}}</span></td>
	</tr>
	{{end}}
</table><br>
<span class="TEXT">The chart below shows the aggregated numbers of issues identified in each category. Solid colored bars represent issues with a confidence level of Certain, and the bars fade as the confidence level falls.</span><br><br>
<table cellpadding="0" cellspacing="0" class="overview_table">
	<tr>
		<td width="70">&nbsp;</td>
		<td width="100">&nbsp;</td>
		<td colspan="10" height="40" align="center" class="label">Number of issues</td>
	</tr>
	<tr>
		<td width="70">&nbsp;</td>
		<td width="90">&nbsp;</td>
		<td width="75"><span class="grad_mark">0</span></td>
		<td width="75"><span class="grad_mark">2</span></td>
		<td width="75"><span class="grad_mark">4</span></td>
		<td width="75"><span class="grad_mark">6</span></td>
		<td width="75"><span class="grad_mark">8</span></td>
		<td width="75"><span class="grad_mark">10</span></td>
		<td width="75"><span class="grad_mark">12</span></td>
		<td width="75"><span class="grad_mark">14</span></td>
		<td width="75"><span class="grad_mark">16</span></td>
	</tr>
	{{range .BarRows}}
	<tr>
		<td class="info">{{.Name}}</td>
		<td colspan="9" height="30">
			<div class="bar-row">
				{{range .Segments}}{{if gt .Width 0}}<span class="bar-segment {{.Class}}" style="width: {{.Width}}px;"></span>{{end}}{{end}}
			</div>
		</td>
		<td>&nbsp;</td>
	</tr>
	{{end}}
</table>

<div class="rule"></div>
<h1>Contents</h1>
{{range .Contents}}
<p class="{{.Class}}"><a href="#{{.Anchor}}">{{.Display}}</a></p>
{{end}}

{{range .IssueGroups}}
<div class="rule"></div>
<span class="BODH0" id="{{.Anchor}}">{{.Number}}. {{.Title}}</span>
<br>
{{if or .PrevAnchor .NextAnchor}}
{{if .PrevAnchor}}<a class="PREVNEXT" href="#{{.PrevAnchor}}">Previous</a>{{end}}
{{if and .PrevAnchor .NextAnchor}}&nbsp;{{end}}
{{if .NextAnchor}}<a class="PREVNEXT" href="#{{.NextAnchor}}">Next</a>{{end}}
<br>
{{end}}
<h2>Summary</h2>
<table cellpadding="0" cellspacing="0" class="summary_table">
<tr>
<td rowspan="4" class="icon" valign="top" align="center"><div class='{{.IconClass}}'></div></td>
<td>Severity:&nbsp;&nbsp;</td>
<td><b>{{.Severity}}</b></td>
</tr>
<tr>
<td>Confidence:&nbsp;&nbsp;</td>
<td><b>{{.Confidence}}</b></td>
</tr>
<tr>
<td>Host:&nbsp;&nbsp;</td>
<td><b>{{if .Host}}{{.Host}}{{else}}Unknown{{end}}</b></td>
</tr>
<tr>
<td>Path:&nbsp;&nbsp;</td>
<td><b>{{if .Path}}{{.Path}}{{else}}/{{end}}</b></td>
</tr>
</table>
{{if .HasIssueDetail}}
<h2>Issue detail</h2>
<span class="TEXT">
{{.IssueDetail}}
{{if .HasInstanceLinks}}
<br><br>There are {{len .InstanceLinks}} instances of this issue:
<ul>
{{range .InstanceLinks}}
<li><a href="#{{.Anchor}}">{{.Display}}</a></li>
{{end}}
</ul>
{{end}}
</span>
{{end}}
{{if .HasIssueBackground}}
<h2>Issue background</h2>
<span class="TEXT">{{.IssueBackground}}</span>
{{end}}
{{if .HasRemediation}}
<h2>Issue remediation</h2>
<span class="TEXT">{{.Remediation}}</span>
{{end}}

{{range .Instances}}
<div class="rule"></div>
<span class="BODH1" id="{{.Anchor}}">{{.Number}}. {{.Title}}</span>
<br>
{{if or .PrevAnchor .NextAnchor}}
{{if .PrevAnchor}}<a class="PREVNEXT" href="#{{.PrevAnchor}}">Previous</a>{{end}}
{{if and .PrevAnchor .NextAnchor}}&nbsp;{{end}}
{{if .NextAnchor}}<a class="PREVNEXT" href="#{{.NextAnchor}}">Next</a>{{end}}
<br>
{{end}}
<h2>Summary</h2>
<table cellpadding="0" cellspacing="0" class="summary_table">
<tr>
<td rowspan="4" class="icon" valign="top" align="center"><div class='{{.IconClass}}'></div></td>
<td>Severity:&nbsp;&nbsp;</td>
<td><b>{{.Severity}}</b></td>
</tr>
<tr>
<td>Confidence:&nbsp;&nbsp;</td>
<td><b>{{.Confidence}}</b></td>
</tr>
<tr>
<td>Host:&nbsp;&nbsp;</td>
<td><b>{{if .Host}}{{.Host}}{{else}}Unknown{{end}}</b></td>
</tr>
<tr>
<td>Path:&nbsp;&nbsp;</td>
<td><b>{{if .Path}}{{.Path}}{{else}}/{{end}}</b></td>
</tr>
</table>
{{range .Notes}}
<p><b>Note:</b> {{.}}</p>
{{end}}
{{if .HasDetail}}
<h2>Issue detail</h2>
<span class="TEXT">{{.Detail}}</span>
{{end}}
{{range .EvidenceBlocks}}
{{if .HasInformation}}
<h2>Information items</h2>
<div class="TEXT">
<ul>
{{range .InformationItems}}<li>{{.}}</li>{{end}}
</ul>
</div>
{{end}}
{{if .HasURL}}
<p class="TEXT"><b>URL:</b> {{.URL}}</p>
{{end}}
{{if .HasRequest}}
<h2>{{.RequestTitle}}</h2>
<div class="rr_div">
	<button type="button" class="copy-btn" onclick="copyCodeBlock(this)" aria-label="Copy {{.RequestTitle}}">Copy</button>
	<pre class="code-block">{{.Request}}</pre>
</div>
{{end}}
{{if .HasResponse}}
<h2>{{.ResponseTitle}}</h2>
<div class="rr_div">
	<button type="button" class="copy-btn" onclick="copyCodeBlock(this)" aria-label="Copy {{.ResponseTitle}}">Copy</button>
	<pre class="code-block">{{.Response}}</pre>
</div>
{{end}}
{{end}}
{{end}}
{{end}}

<div class="rule"></div>
<p class="TEXT">Report generated on {{.GeneratedAt}}.</p>
<p class="TEXT">This report was produced from Burp Suite export data.</p>

</div>
<script>
function copyCodeBlock(button) {
	if (!button) {
		return;
	}
	var container = button.closest('.rr_div');
	if (!container) {
		return;
	}
	var pre = container.querySelector('.code-block');
	if (!pre) {
		return;
	}
	var original = button.getAttribute('data-original-text');
	if (!original) {
		original = button.textContent;
		button.setAttribute('data-original-text', original);
	}
	var text = pre.textContent || pre.innerText || '';
	function showResult(success) {
		if (success) {
			button.textContent = 'Copied!';
			button.classList.add('copied');
		} else {
			button.textContent = 'Failed';
			button.classList.remove('copied');
		}
		setTimeout(function () {
			button.textContent = original;
			button.classList.remove('copied');
		}, 2000);
	}
	function fallbackCopy() {
		var temp = document.createElement('textarea');
		temp.value = text;
		temp.setAttribute('readonly', '');
		temp.style.position = 'fixed';
		temp.style.top = '-1000px';
		temp.style.opacity = '0';
		document.body.appendChild(temp);
		temp.focus({ preventScroll: true });
		temp.select();
		if (typeof temp.setSelectionRange === 'function') {
			temp.setSelectionRange(0, temp.value.length);
		}
		var success = false;
		try {
			success = document.execCommand('copy');
		} catch (err) {
			success = false;
		}
		document.body.removeChild(temp);
		showResult(success);
	}
	var canUseClipboard = typeof window !== 'undefined' && window.isSecureContext && navigator.clipboard && typeof navigator.clipboard.writeText === 'function';
	if (canUseClipboard) {
		navigator.clipboard.writeText(text).then(function () {
			showResult(true);
		}).catch(function () {
			fallbackCopy();
		});
	} else {
		fallbackCopy();
	}
}
</script>
</body>
</html>`

var yellow = color.New(color.Bold, color.FgYellow).SprintfFunc()
var red = color.New(color.Bold, color.FgRed).SprintfFunc()
var cyan = color.New(color.Bold, color.FgCyan).SprintfFunc()
var green = color.New(color.Bold, color.FgGreen).SprintfFunc()

// GenerateReport generates HTML report from Burp JSON export
func GenerateReport(inputFile, outputFile, format string) error {
	fmt.Fprintf(color.Output, "%v Generating report from %v\n", cyan(" [i] INFO:"), inputFile)

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return fmt.Errorf("input file '%s' not found", inputFile)
	}

	burpData, err := loadBurpData(inputFile)
	if err != nil {
		return fmt.Errorf("failed to load Burp data: %w", err)
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "burp"
	}

	switch format {
	case "burp":
		tplData, err := buildTemplateData(burpData)
		if err != nil {
			return fmt.Errorf("failed to prepare report data: %w", err)
		}
		if err := generateBurpHTMLReport(tplData, outputFile); err != nil {
			return fmt.Errorf("failed to generate Burp-style report: %w", err)
		}

	case "classic":
		if err := generateClassicHTMLReport(burpData, outputFile); err != nil {
			return fmt.Errorf("failed to generate classic report: %w", err)
		}

	case "both", "all":
		tplData, err := buildTemplateData(burpData)
		if err != nil {
			return fmt.Errorf("failed to prepare report data: %w", err)
		}

		burpOut := outputFile
		classicOut := ensureSuffix(outputFile, "_classic.html")

		if err := generateBurpHTMLReport(tplData, burpOut); err != nil {
			return fmt.Errorf("failed to generate Burp-style report: %w", err)
		}
		if err := generateClassicHTMLReport(burpData, classicOut); err != nil {
			return fmt.Errorf("failed to generate classic report: %w", err)
		}

	default:
		return fmt.Errorf("unknown format '%s'. Supported values: burp, classic, both", format)
	}

	return nil
}

func ensureSuffix(path string, suffix string) string {
	ext := filepath.Ext(path)
	if ext != "" {
		return strings.TrimSuffix(path, ext) + suffix
	}
	return path + suffix
}

func loadBurpData(jsonFile string) ([]BurpItem, error) {
	data, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var burpData []BurpItem
	if err := json.Unmarshal(data, &burpData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return burpData, nil
}

func decodeBase64Safe(data string) string {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return fmt.Sprintf("[Decode Error: %v]", err)
	}
	return string(decoded)
}

func extractAllEvidence(evidenceList []Evidence) []ProcessedEvidence {
	if len(evidenceList) == 0 {
		return []ProcessedEvidence{}
	}

	var allEvidence []ProcessedEvidence

	for _, evidence := range evidenceList {
		processed := ProcessedEvidence{
			Type:             evidence.Type,
			InformationItems: evidence.InformationItems,
		}

		if evidence.RequestResponse != nil {
			reqResp := evidence.RequestResponse
			processed.URL = reqResp.URL

			var requestHTML strings.Builder
			for _, segment := range reqResp.Request {
				if segment.Data != "" {
					decoded := decodeBase64Safe(segment.Data)
					escaped := html.EscapeString(decoded)
					escaped = strings.ReplaceAll(escaped, "\r\n", "\n")
					escaped = strings.ReplaceAll(escaped, "\r", "\n")
					escaped = strings.ReplaceAll(escaped, "\t", "    ")
					if segment.Type == "HighlightSegment" {
						requestHTML.WriteString(fmt.Sprintf(`<span class="HIGHLIGHT">%s</span>`, escaped))
					} else {
						requestHTML.WriteString(escaped)
					}
				}
			}

			var responseHTML strings.Builder
			for _, segment := range reqResp.Response {
				if segment.Type == "SnipSegment" {
					responseHTML.WriteString(fmt.Sprintf("\n[... %d bytes snipped ...]\n", segment.Length))
				} else if segment.Data != "" {
					decoded := decodeBase64Safe(segment.Data)
					escaped := html.EscapeString(decoded)
					escaped = strings.ReplaceAll(escaped, "\r\n", "\n")
					escaped = strings.ReplaceAll(escaped, "\r", "\n")
					escaped = strings.ReplaceAll(escaped, "\t", "    ")
					if segment.Type == "HighlightSegment" {
						responseHTML.WriteString(fmt.Sprintf(`<span class="HIGHLIGHT">%s</span>`, escaped))
					} else {
						responseHTML.WriteString(escaped)
					}
				}
			}

			if requestHTML.Len() > 0 {
				processed.Request = requestHTML.String()
			}
			if responseHTML.Len() > 0 {
				processed.Response = responseHTML.String()
			}
		}

		if evidence.Type == "DiffableEvidence" {
			if evidence.FirstEvidence != nil {
				firstEv := extractAllEvidence([]Evidence{*evidence.FirstEvidence})
				if len(firstEv) > 0 {
					processed.FirstEvidence = &firstEv[0]
				}
			}
			if evidence.SecondEvidence != nil {
				secondEv := extractAllEvidence([]Evidence{*evidence.SecondEvidence})
				if len(secondEv) > 0 {
					processed.SecondEvidence = &secondEv[0]
				}
			}
		}

		allEvidence = append(allEvidence, processed)
	}

	return allEvidence
}

func generateBurpHTMLReport(tplData TemplateData, outputFile string) error {
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, tplData); err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	fmt.Printf("✅ Burp-style report generated: %s\n", outputFile)
	fmt.Printf("   Total issues: %d\n", tplData.TotalIssues)
	return nil
}

func generateClassicHTMLReport(burpData []BurpItem, outputFile string) error {
	type classicIssue struct {
		Item  BurpItem
		Issue Issue
	}

	severityCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	issues := make([]classicIssue, 0, len(burpData))
	for _, item := range burpData {
		if item.Type != "issue_found" || item.Issue == nil {
			continue
		}
		issueCopy := *item.Issue
		severity := strings.ToLower(issueCopy.Severity)
		if severity == "informational" {
			severity = "info"
		}
		if _, ok := severityCounts[severity]; ok {
			severityCounts[severity]++
		} else {
			severityCounts["info"]++
		}
		issues = append(issues, classicIssue{Item: item, Issue: issueCopy})
	}

	severityOrder := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}

	sort.SliceStable(issues, func(i, j int) bool {
		sevI := strings.ToLower(issues[i].Issue.Severity)
		sevJ := strings.ToLower(issues[j].Issue.Severity)
		if sevI == "informational" {
			sevI = "info"
		}
		if sevJ == "informational" {
			sevJ = "info"
		}
		orderI, okI := severityOrder[sevI]
		orderJ, okJ := severityOrder[sevJ]
		if !okI {
			orderI = 999
		}
		if !okJ {
			orderJ = 999
		}
		if orderI == orderJ {
			return strings.ToLower(issues[i].Issue.Name) < strings.ToLower(issues[j].Issue.Name)
		}
		return orderI < orderJ
	})

	var htmlContent strings.Builder
	htmlContent.Grow(256 * len(issues))
	htmlContent.WriteString(getClassicHTMLHeader(len(issues), severityCounts))

	for idx, entry := range issues {
		issue := entry.Issue
		severity := strings.ToLower(issue.Severity)
		if severity == "informational" {
			severity = "info"
		}
		issueID := html.EscapeString(entry.Item.ID)
		name := html.EscapeString(issue.Name)
		origin := html.EscapeString(issue.Origin)
		path := html.EscapeString(issue.Path)
		confidence := html.EscapeString(issue.Confidence)

		htmlContent.WriteString(fmt.Sprintf(`
					<tr class="issue-row" data-severity="%s">
						<td>%d</td>
						<td>%s</td>
						<td>%s</td>
						<td>%s</td>
						<td>%s%s</td>
						<td>%s</td>
						<td><button class="view-details-btn" onclick="scrollToIssue(%d)">View Details</button></td>
					</tr>
		`, severity, idx+1, issueID, getClassicSeverityBadge(severity), name, origin, path, confidence, idx))
	}

	htmlContent.WriteString(`
			</tbody>
		</table>
	</div>

	<div class="expand-all">
		<button onclick="toggleAll()">Expand/Collapse All</button>
	</div>

	<div class="issues">
`)

	if len(issues) == 0 {
		htmlContent.WriteString(`
			<div class="no-issues">
				<h2>No security issues found</h2>
				<p>The scan completed without identifying any vulnerabilities.</p>
			</div>

`)
	} else {
		for idx, entry := range issues {
			issue := entry.Issue
			severity := strings.ToLower(issue.Severity)
			if severity == "informational" {
				severity = "info"
			}
			name := html.EscapeString(issue.Name)
			origin := html.EscapeString(issue.Origin)
			path := html.EscapeString(issue.Path)
			confidence := html.EscapeString(issue.Confidence)

			description := issue.Description
			if description == "" {
				description = issue.IssueBackground
			}
			if description == "" {
				description = "No description available"
			}

			remediation := issue.RemediationBackground
			if remediation == "" {
				remediation = "No remediation information available"
			}

			allEvidence := extractAllEvidenceClassic(issue.Evidence)

			htmlContent.WriteString(fmt.Sprintf(`
			<div class="issue" id="issue-card-%d" data-severity="%s">
				<div class="issue-header %s" onclick="toggleIssue(%d)">
					<div class="issue-title">
						<h2>%s</h2>
						%s
					</div>
					<div class="issue-meta">
						<strong>URL:</strong> %s%s |
						<strong>Confidence:</strong> %s
					</div>
				</div>

				<div class="issue-details" id="issue-%d">
					<div class="issue-metadata">
						<h3 style="margin-bottom: 15px;">📊 Issue Metadata</h3>
						<div class="metadata-grid">
							<div class="metadata-item">
								<div class="metadata-label">Issue ID</div>
								<div class="metadata-value">%s</div>
							</div>
							<div class="metadata-item">
								<div class="metadata-label">Type Index</div>
								<div class="metadata-value">%d</div>
							</div>
							<div class="metadata-item">
								<div class="metadata-label">Serial Number</div>
								<div class="metadata-value">%s</div>
							</div>
							<div class="metadata-item">
								<div class="metadata-label">Caption</div>
								<div class="metadata-value">%s</div>
							</div>
						</div>
					</div>

					<div class="detail-section">
						<h3>📋 Description</h3>
						<div class="detail-content">
							%s
						</div>
					</div>

					<div class="detail-section">
						<h3>🔧 Remediation</h3>
						<div class="detail-content">
							%s
						</div>
					</div>
`, idx, severity, severity, idx, name, getClassicSeverityBadge(severity), origin, path, confidence,
				idx, html.EscapeString(entry.Item.ID), issue.TypeIndex,
				html.EscapeString(issue.SerialNumber), html.EscapeString(issue.Caption),
				description, remediation))

			if len(allEvidence) > 0 {
				htmlContent.WriteString(`
					<div class="evidence-section">
						<h3>🔍 Evidence Details</h3>
`)
				for evIdx, evidence := range allEvidence {
					evType := html.EscapeString(evidence.Type)
					htmlContent.WriteString(fmt.Sprintf(`
						<div class="evidence-item">
							<div class="evidence-header">
								Evidence #%d <span class="badge badge-primary">%s</span>
							</div>
`, evIdx+1, evType))

					if evidence.URL != "" {
						htmlContent.WriteString(fmt.Sprintf(`
							<div style="margin-bottom: 10px;">
								<strong>URL:</strong> <code>%s</code>
							</div>
`, html.EscapeString(evidence.URL)))
					}

					if len(evidence.InformationItems) > 0 {
						htmlContent.WriteString(`
							<div class="info-list">
								<strong>Information Items:</strong>
								<ul>
`)
						for _, item := range evidence.InformationItems {
							htmlContent.WriteString(fmt.Sprintf("<li>%s</li>", html.EscapeString(item)))
						}
						htmlContent.WriteString(`
							</ul>
							</div>
`)
					}

					if evidence.Request != "" {
						htmlContent.WriteString(fmt.Sprintf(`
							<div class="detail-section">
								<h4>📤 HTTP Request</h4>
						<div class="code-wrapper">
							<button type="button" class="code-copy-btn" onclick="copyClassicCode(this)">Copy</button>
							<pre class="http-block">%s</pre>
						</div>
							</div>
`, evidence.Request))
					}

					if evidence.Response != "" {
						htmlContent.WriteString(fmt.Sprintf(`
							<div class="detail-section">
								<h4>📥 HTTP Response</h4>
						<div class="code-wrapper">
							<button type="button" class="code-copy-btn" onclick="copyClassicCode(this)">Copy</button>
							<pre class="http-block">%s</pre>
						</div>
							</div>
`, evidence.Response))
					}

					if evidence.FirstEvidence != nil {
						htmlContent.WriteString(`
							<div style="margin-top: 15px;">
								<h4>First Evidence (Original Request)</h4>
`)
						firstEv := evidence.FirstEvidence
						if firstEv.URL != "" {
							htmlContent.WriteString(fmt.Sprintf("<p><strong>URL:</strong> <code>%s</code></p>",
								html.EscapeString(firstEv.URL)))
						}
						if firstEv.Request != "" {
							htmlContent.WriteString(fmt.Sprintf(`<div class="http-block">%s</div>`, firstEv.Request))
						}
						if firstEv.Response != "" {
							htmlContent.WriteString(fmt.Sprintf(`<div class="http-block" style="margin-top: 10px;">%s</div>`,
								firstEv.Response))
						}
						htmlContent.WriteString("</div>")
					}

					if evidence.SecondEvidence != nil {
						htmlContent.WriteString(`
							<div style="margin-top: 15px;">
								<h4>Second Evidence (Modified Request)</h4>
`)
						secondEv := evidence.SecondEvidence
						if secondEv.URL != "" {
							htmlContent.WriteString(fmt.Sprintf("<p><strong>URL:</strong> <code>%s</code></p>",
								html.EscapeString(secondEv.URL)))
						}
						if secondEv.Request != "" {
							htmlContent.WriteString(fmt.Sprintf(`<div class="http-block">%s</div>`, secondEv.Request))
						}
						if secondEv.Response != "" {
							htmlContent.WriteString(fmt.Sprintf(`<div class="http-block" style="margin-top: 10px;">%s</div>`,
								secondEv.Response))
						}
						htmlContent.WriteString("</div>")
					}

					htmlContent.WriteString(`
						</div>
`)
				}

				htmlContent.WriteString(`
					</div>
`)
			}

			htmlContent.WriteString(`
				</div>
			</div>
`)
		}
	}

	htmlContent.WriteString(getClassicHTMLFooter())

	if err := os.WriteFile(outputFile, []byte(htmlContent.String()), 0644); err != nil {
		return fmt.Errorf("failed to write classic report: %w", err)
	}

	fmt.Printf("✅ Classic report generated: %s\n", outputFile)
	fmt.Printf("   High:   %d\n", severityCounts["high"])
	fmt.Printf("   Medium: %d\n", severityCounts["medium"])
	fmt.Printf("   Low:    %d\n", severityCounts["low"])
	fmt.Printf("   Info:   %d\n", severityCounts["info"])
	fmt.Printf("   Total:  %d issues\n", len(issues))
	return nil
}

func getClassicSeverityColor(severity string) string {
	colors := map[string]string{
		"critical":      "#8b0000",
		"high":          "#dc3545",
		"medium":        "#fd7e14",
		"low":           "#ffc107",
		"info":          "#17a2b8",
		"informational": "#17a2b8",
	}
	if color, ok := colors[strings.ToLower(severity)]; ok {
		return color
	}
	return "#6c757d"
}

func getClassicSeverityBadge(severity string) string {
	color := getClassicSeverityColor(severity)
	return fmt.Sprintf(`<span class="severity-badge" style="background-color: %s;">%s</span>`,
		color, strings.ToUpper(severity))
}

func getClassicHTMLHeader(totalIssues int, severityCounts map[string]int) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Burp Suite Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .report-meta {
            opacity: 0.9;
            font-size: 0.95em;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }

        .summary-card.critical { border-left-color: #8b0000; }
        .summary-card.high { border-left-color: #dc3545; }
        .summary-card.medium { border-left-color: #fd7e14; }
        .summary-card.low { border-left-color: #ffc107; }
        .summary-card.info { border-left-color: #17a2b8; }

        .summary-card h3 {
            font-size: 0.9em;
            text-transform: uppercase;
            color: #666;
            margin-bottom: 10px;
        }

        .summary-card .count {
            font-size: 2.5em;
            font-weight: bold;
        }

        .issue {
            background: white;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .issue-header {
            padding: 20px;
            border-left: 5px solid;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .issue-header:hover {
            background-color: #f8f9fa;
        }

        .issue-header.critical { border-left-color: #8b0000; }
        .issue-header.high { border-left-color: #dc3545; }
        .issue-header.medium { border-left-color: #fd7e14; }
        .issue-header.low { border-left-color: #ffc107; }
        .issue-header.info { border-left-color: #17a2b8; }

        .issue-title {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .issue-title h2 {
            font-size: 1.4em;
            color: #2c3e50;
        }

        .severity-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }

        .issue-meta {
            color: #666;
            font-size: 0.9em;
        }

        .issue-meta strong {
            color: #333;
        }

        .issue-details {
            display: none;
            padding: 20px;
            border-top: 1px solid #e9ecef;
            background-color: #f8f9fa;
        }

        .issue-details.active {
            display: block;
        }

        .detail-section {
            margin-bottom: 25px;
        }

        .detail-section h3, .detail-section h4 {
            color: #495057;
            margin-bottom: 10px;
            padding-bottom: 5px;
            border-bottom: 2px solid #dee2e6;
        }

        .detail-content {
            background: white;
            padding: 15px;
            border-radius: 5px;
            line-height: 1.8;
        }

        .code-wrapper {
            position: relative;
            background: #0d1117;
            border: 1px solid #2d3748;
            border-radius: 6px;
            padding: 16px;
            margin-top: 10px;
            overflow: auto;
            max-height: 320px;
        }

        .http-block {
            margin: 0;
            color: #d4d4d4;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.9em;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .code-copy-btn {
            position: absolute;
            top: 10px;
            right: 12px;
            background: #667eea;
            color: #ffffff;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8em;
            transition: background 0.2s ease-in-out;
        }

        .code-copy-btn:hover {
            background: #4c59d9;
        }

        .code-copy-btn.copied {
            background: #2d865d;
        }

        .highlight {
            background-color: #ffff00;
            color: #000;
            padding: 2px 4px;
            border-radius: 2px;
        }

        .code-wrapper .highlight {
            background-color: #fcf446;
        }

        footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
            margin-top: 40px;
        }

        .no-issues {
            background: white;
            padding: 40px;
            text-align: center;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .expand-all {
            text-align: right;
            margin-bottom: 15px;
        }

        .expand-all button {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
        }

        .expand-all button:hover {
            background: #764ba2;
        }

        .filter-section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .filter-section h3 {
            margin-bottom: 15px;
            color: #2c3e50;
        }

        .filter-checkboxes {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }

        .filter-checkbox {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .filter-checkbox input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }

        .filter-checkbox label {
            cursor: pointer;
            font-weight: 500;
        }

        .issues-table {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        .issues-table table {
            width: 100%%;
            border-collapse: collapse;
        }

        .issues-table th {
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }

        .issues-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #e9ecef;
        }

        .issues-table tr:hover {
            background-color: #f8f9fa;
        }

        .view-details-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
        }

        .view-details-btn:hover {
            background: #764ba2;
        }

        .issue-metadata {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
        }

        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }

        .metadata-item {
            padding: 8px;
            background: white;
            border-radius: 4px;
        }

        .metadata-label {
            font-weight: 600;
            color: #495057;
            font-size: 0.85em;
            margin-bottom: 3px;
        }

        .metadata-value {
            color: #212529;
            font-size: 0.9em;
            word-break: break-all;
        }

        .info-list {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px 15px;
            margin: 10px 0;
        }

        .info-list ul {
            margin: 5px 0;
            padding-left: 20px;
        }

        .evidence-section {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid #dee2e6;
        }

        .evidence-item {
            margin-bottom: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }

        .evidence-header {
            font-weight: 600;
            color: #495057;
            margin-bottom: 10px;
            padding-bottom: 5px;
            border-bottom: 1px solid #dee2e6;
        }

        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: 500;
        }

        .badge-primary {
            background: #667eea;
            color: white;
        }

        @media (max-width: 768px) {
            header {
                padding: 30px 15px;
            }

            .issue {
                margin-left: 0;
                margin-right: 0;
            }

            .issue-title {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }

            .issues-table {
                overflow-x: auto;
            }

            .filter-checkboxes {
                flex-direction: column;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Burp Suite Security Report</h1>
            <div class="report-meta">
                <p>Generated: %s</p>
                <p>Total Issues Found: %d</p>
            </div>
        </header>

        <div class="summary">
            <div class="summary-card critical">
                <h3>Critical Severity</h3>
                <div class="count" style="color: #8b0000;">%d</div>
            </div>
            <div class="summary-card high">
                <h3>High Severity</h3>
                <div class="count" style="color: #dc3545;">%d</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Severity</h3>
                <div class="count" style="color: #fd7e14;">%d</div>
            </div>
            <div class="summary-card low">
                <h3>Low Severity</h3>
                <div class="count" style="color: #ffc107;">%d</div>
            </div>
            <div class="summary-card info">
                <h3>Informational</h3>
                <div class="count" style="color: #17a2b8;">%d</div>
            </div>
        </div>

        <div class="filter-section">
            <h3>🔍 Filter by Severity</h3>
            <div class="filter-checkboxes">
                <div class="filter-checkbox">
                    <input type="checkbox" id="filter-critical" checked onchange="filterIssues()">
                    <label for="filter-critical">Critical</label>
                </div>
                <div class="filter-checkbox">
                    <input type="checkbox" id="filter-high" checked onchange="filterIssues()">
                    <label for="filter-high">High</label>
                </div>
                <div class="filter-checkbox">
                    <input type="checkbox" id="filter-medium" checked onchange="filterIssues()">
                    <label for="filter-medium">Medium</label>
                </div>
                <div class="filter-checkbox">
                    <input type="checkbox" id="filter-low" checked onchange="filterIssues()">
                    <label for="filter-low">Low</label>
                </div>
                <div class="filter-checkbox">
                    <input type="checkbox" id="filter-info" checked onchange="filterIssues()">
                    <label for="filter-info">Informational</label>
                </div>
            </div>
        </div>

        <div class="issues-table">
            <table id="issues-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Issue ID</th>
                        <th>Severity</th>
                        <th>Issue Name</th>
                        <th>URL</th>
                        <th>Confidence</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
`, time.Now().Format("2006-01-02 15:04:05"), totalIssues,
		severityCounts["critical"], severityCounts["high"], severityCounts["medium"], severityCounts["low"], severityCounts["info"])
}

func getClassicHTMLFooter() string {
	return `
        </div>

        <footer>
            <p>Report generated from Burp Suite export data</p>
            <p>For security purposes, this report should be kept confidential</p>
        </footer>
    </div>

    <script>
        function toggleIssue(index) {
            const details = document.getElementById('issue-' + index);
            details.classList.toggle('active');
        }

        function toggleAll() {
            const allDetails = document.querySelectorAll('.issue-details');
            const anyExpanded = Array.from(allDetails).some(detail => detail.classList.contains('active'));

            allDetails.forEach(detail => {
                if (anyExpanded) {
                    detail.classList.remove('active');
                } else {
                    detail.classList.add('active');
                }
            });
        }

        function filterIssues() {
            const filters = {
                critical: document.getElementById('filter-critical').checked,
                high: document.getElementById('filter-high').checked,
                medium: document.getElementById('filter-medium').checked,
                low: document.getElementById('filter-low').checked,
                info: document.getElementById('filter-info').checked
            };

            const tableRows = document.querySelectorAll('.issue-row');
            tableRows.forEach(row => {
                const severity = row.getAttribute('data-severity');
                if (filters[severity]) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });

            const issueCards = document.querySelectorAll('.issue');
            issueCards.forEach(card => {
                const header = card.querySelector('.issue-header');
                const severity = header.classList.contains('critical') ? 'critical' :
                                header.classList.contains('high') ? 'high' :
                                header.classList.contains('medium') ? 'medium' :
                                header.classList.contains('low') ? 'low' : 'info';

                if (filters[severity]) {
                    card.style.display = '';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        function scrollToIssue(index) {
            const issueElement = document.getElementById('issue-card-' + index);
            if (issueElement) {
                issueElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
                const details = document.getElementById('issue-' + index);
                if (details && !details.classList.contains('active')) {
                    details.classList.add('active');
                }

                issueElement.style.boxShadow = '0 0 20px rgba(102, 126, 234, 0.5)';
                setTimeout(() => {
                    issueElement.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
                }, 2000);
            }
        }

        function copyClassicCode(button) {
            if (!button) {
                return;
            }
            const wrapper = button.closest('.code-wrapper');
            if (!wrapper) {
                return;
            }
            const pre = wrapper.querySelector('.http-block');
            if (!pre) {
                return;
            }
            let original = button.getAttribute('data-original-text');
            if (!original) {
                original = button.textContent;
                button.setAttribute('data-original-text', original);
            }
            const text = pre.textContent || pre.innerText || '';
            const showResult = (success) => {
                if (success) {
                    button.textContent = 'Copied!';
                    button.classList.add('copied');
                } else {
                    button.textContent = 'Failed';
                    button.classList.remove('copied');
                }
                setTimeout(() => {
                    button.textContent = original;
                    button.classList.remove('copied');
                }, 2000);
            };
            const fallbackCopy = () => {
                const temp = document.createElement('textarea');
                temp.value = text;
                temp.setAttribute('readonly', '');
                temp.style.position = 'fixed';
                temp.style.top = '-1000px';
                temp.style.opacity = '0';
                document.body.appendChild(temp);
                temp.focus({ preventScroll: true });
                temp.select();
                if (typeof temp.setSelectionRange === 'function') {
                    temp.setSelectionRange(0, temp.value.length);
                }
                let success = false;
                try {
                    success = document.execCommand('copy');
                } catch (err) {
                    success = false;
                }
                document.body.removeChild(temp);
                showResult(success);
            };
            const canUseClipboard = typeof window !== 'undefined' && window.isSecureContext && navigator.clipboard && typeof navigator.clipboard.writeText === 'function';
            if (canUseClipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    showResult(true);
                }).catch(() => {
                    fallbackCopy();
                });
            } else {
                fallbackCopy();
            }
        }
    </script>
</body>
</html>`
}

func extractAllEvidenceClassic(evidenceList []Evidence) []ProcessedEvidence {
	if len(evidenceList) == 0 {
		return []ProcessedEvidence{}
	}

	var allEvidence []ProcessedEvidence

	for _, evidence := range evidenceList {
		processed := ProcessedEvidence{
			Type:             evidence.Type,
			InformationItems: evidence.InformationItems,
		}

		if evidence.RequestResponse != nil {
			reqResp := evidence.RequestResponse
			processed.URL = reqResp.URL

			var requestHTML strings.Builder
			for _, segment := range reqResp.Request {
				if segment.Data != "" {
					decoded := decodeBase64Safe(segment.Data)
					escaped := html.EscapeString(decoded)
					escaped = strings.ReplaceAll(escaped, "\r\n", "\n")
					escaped = strings.ReplaceAll(escaped, "\r", "\n")
					escaped = strings.ReplaceAll(escaped, "\t", "    ")
					if segment.Type == "HighlightSegment" {
						requestHTML.WriteString(fmt.Sprintf(`<span class="highlight">%s</span>`, escaped))
					} else {
						requestHTML.WriteString(escaped)
					}
				}
			}

			var responseHTML strings.Builder
			for _, segment := range reqResp.Response {
				if segment.Type == "SnipSegment" {
					responseHTML.WriteString(fmt.Sprintf("\n[... %d bytes snipped ...]\n", segment.Length))
				} else if segment.Data != "" {
					decoded := decodeBase64Safe(segment.Data)
					escaped := html.EscapeString(decoded)
					escaped = strings.ReplaceAll(escaped, "\r\n", "\n")
					escaped = strings.ReplaceAll(escaped, "\r", "\n")
					escaped = strings.ReplaceAll(escaped, "\t", "    ")
					if segment.Type == "HighlightSegment" {
						responseHTML.WriteString(fmt.Sprintf(`<span class="highlight">%s</span>`, escaped))
					} else {
						responseHTML.WriteString(escaped)
					}
				}
			}

			if requestHTML.Len() > 0 {
				processed.Request = requestHTML.String()
			}
			if responseHTML.Len() > 0 {
				processed.Response = responseHTML.String()
			}
		}

		if evidence.Type == "DiffableEvidence" {
			if evidence.FirstEvidence != nil {
				firstEv := extractAllEvidenceClassic([]Evidence{*evidence.FirstEvidence})
				if len(firstEv) > 0 {
					processed.FirstEvidence = &firstEv[0]
				}
			}
			if evidence.SecondEvidence != nil {
				secondEv := extractAllEvidenceClassic([]Evidence{*evidence.SecondEvidence})
				if len(secondEv) > 0 {
					processed.SecondEvidence = &secondEv[0]
				}
			}
		}

		allEvidence = append(allEvidence, processed)
	}

	return allEvidence
}

func buildTemplateData(burpData []BurpItem) (TemplateData, error) {
	severityOrder := []string{"high", "medium", "low", "information", "false_positive"}
	confidenceOrder := []string{"certain", "firm", "tentative"}

	severityCounts := make(map[string]map[string]int)
	for _, sev := range severityOrder {
		severityCounts[sev] = map[string]int{"certain": 0, "firm": 0, "tentative": 0}
	}

	groupMap := make(map[string]*issueGroupAggregation)
	firstIndex := 0
	totalIssues := 0

	for _, item := range burpData {
		if item.Type != "issue_found" || item.Issue == nil {
			continue
		}
		issue := *item.Issue
		totalIssues++

		severity := normalizeSeverity(issue.Severity)
		confidence := normalizeConfidence(issue.Confidence)
		if _, ok := severityCounts[severity]; !ok {
			severityCounts[severity] = map[string]int{"certain": 0, "firm": 0, "tentative": 0}
		}
		severityCounts[severity][confidence]++

		key := strings.TrimSpace(issue.Name)
		if key == "" {
			key = fmt.Sprintf("Issue %d", totalIssues)
		}

		agg, ok := groupMap[key]
		if !ok {
			agg = &issueGroupAggregation{Name: key, FirstIndex: firstIndex, Severity: severity}
			groupMap[key] = agg
			firstIndex++
		}
		agg.Issues = append(agg.Issues, groupedIssue{Item: item, Issue: issue})
		if severityRank(severity) < severityRank(agg.Severity) {
			agg.Severity = severity
		}
	}

	groups := make([]*issueGroupAggregation, 0, len(groupMap))
	for _, group := range groupMap {
		groups = append(groups, group)
	}

	sort.Slice(groups, func(i, j int) bool {
		ri := severityRank(groups[i].Severity)
		rj := severityRank(groups[j].Severity)
		if ri == rj {
			return groups[i].FirstIndex < groups[j].FirstIndex
		}
		return ri < rj
	})

	summaryRows := make([]SeveritySummary, 0, len(severityOrder))
	barRows := make([]BarRow, 0, len(severityOrder))
	for _, sev := range severityOrder {
		counts := severityCounts[sev]
		row := SeveritySummary{
			Name:      severityDisplay(sev),
			Lower:     severityClass(sev),
			Certain:   counts["certain"],
			Firm:      counts["firm"],
			Tentative: counts["tentative"],
		}
		row.Total = row.Certain + row.Firm + row.Tentative
		summaryRows = append(summaryRows, row)

		segments := make([]BarSegment, 0, len(confidenceOrder))
		for _, conf := range confidenceOrder {
			segments = append(segments, newBarSegment(sev, conf, counts[conf]))
		}
		barRows = append(barRows, BarRow{Name: row.Name, Segments: segments})
	}

	contents := make([]TOCEntry, 0)
	issueGroups := make([]IssueGroupTemplate, 0, len(groups))

	for idx, group := range groups {
		groupNumber := idx + 1
		base := group.Issues[0].Issue
		severity := normalizeSeverity(base.Severity)

		confidenceSet := make(map[string]struct{})
		for _, inst := range group.Issues {
			confidenceSet[normalizeConfidence(inst.Issue.Confidence)] = struct{}{}
		}

		confidenceLower := normalizeConfidence(base.Confidence)
		if confidenceLower == "" {
			confidenceLower = "certain"
		}
		confidenceText := "Varies"
		if len(confidenceSet) <= 1 {
			for c := range confidenceSet {
				confidenceLower = c
			}
			confidenceText = confidenceDisplay(confidenceLower)
		} else if len(confidenceSet) == 0 {
			confidenceText = confidenceDisplay(confidenceLower)
		}

		groupTemplate := IssueGroupTemplate{
			Anchor:          fmt.Sprintf("%d", groupNumber),
			Number:          fmt.Sprintf("%d", groupNumber),
			Title:           strings.TrimSpace(group.Name),
			Severity:        severityDisplay(severity),
			SeverityLower:   severityClass(severity),
			Confidence:      confidenceText,
			ConfidenceLower: confidenceLower,
			IconClass:       fmt.Sprintf("scan_issue_%s_%s_rpt", severityClass(severity), confidenceLower),
			Host:            strings.TrimSpace(base.Origin),
			Path:            strings.TrimSpace(base.Path),
		}

		detail := chooseIssueDetail(base)
		groupTemplate.IssueDetail = detail
		groupTemplate.HasIssueDetail = true

		if strings.TrimSpace(base.IssueBackground) != "" {
			groupTemplate.IssueBackground = toHTML(base.IssueBackground)
			groupTemplate.HasIssueBackground = true
		}

		remediation := strings.TrimSpace(base.RemediationBackground)
		if remediation == "" {
			groupTemplate.Remediation = template.HTML("<em>No remediation guidance provided.</em>")
		} else {
			groupTemplate.Remediation = toHTML(remediation)
		}
		groupTemplate.HasRemediation = true

		contents = append(contents, TOCEntry{
			Class:   "TOCH0",
			Anchor:  groupTemplate.Anchor,
			Display: fmt.Sprintf("%d. %s", groupNumber, groupTemplate.Title),
		})

		instances := make([]IssueInstanceTemplate, 0, len(group.Issues))
		instanceLinks := make([]InstanceLink, 0)

		for instIdx, inst := range group.Issues {
			instanceNumber := fmt.Sprintf("%d.%d", groupNumber, instIdx+1)
			instanceAnchor := instanceNumber
			instSeverity := normalizeSeverity(inst.Issue.Severity)
			instConfidence := normalizeConfidence(inst.Issue.Confidence)
			if instConfidence == "" {
				instConfidence = "certain"
			}
			fullURL := buildFullURL(inst.Issue.Origin, inst.Issue.Path)
			instanceTemplate := IssueInstanceTemplate{
				Anchor:          instanceAnchor,
				Number:          instanceNumber,
				Title:           fullURL,
				Severity:        severityDisplay(instSeverity),
				SeverityLower:   severityClass(instSeverity),
				Confidence:      confidenceDisplay(instConfidence),
				ConfidenceLower: instConfidence,
				Host:            strings.TrimSpace(inst.Issue.Origin),
				Path:            strings.TrimSpace(inst.Issue.Path),
				Detail:          detail,
				HasDetail:       true,
				IconClass:       fmt.Sprintf("scan_issue_%s_%s_rpt", severityClass(instSeverity), instConfidence),
			}
			if note := strings.TrimSpace(inst.Issue.Caption); note != "" && note != "/" {
				instanceTemplate.Notes = append(instanceTemplate.Notes, note)
			}

			evidenceBlocks := buildEvidenceBlocks(extractAllEvidence(inst.Issue.Evidence))
			if len(evidenceBlocks) > 0 {
				instanceTemplate.EvidenceBlocks = evidenceBlocks
				instanceTemplate.HasEvidence = true
			}

			instances = append(instances, instanceTemplate)

			if len(group.Issues) > 1 {
				link := InstanceLink{
					Anchor:  instanceAnchor,
					Display: fmt.Sprintf("%s. %s", instanceNumber, fullURL),
				}
				instanceLinks = append(instanceLinks, link)
				contents = append(contents, TOCEntry{
					Class:   "TOCH1",
					Anchor:  instanceAnchor,
					Display: link.Display,
				})
			}
		}

		if len(instanceLinks) > 0 {
			groupTemplate.InstanceLinks = instanceLinks
			groupTemplate.HasInstanceLinks = true
		}

		groupTemplate.Instances = instances
		issueGroups = append(issueGroups, groupTemplate)
	}

	for i := range issueGroups {
		if i > 0 {
			issueGroups[i].PrevAnchor = issueGroups[i-1].Anchor
		}
		if i < len(issueGroups)-1 {
			issueGroups[i].NextAnchor = issueGroups[i+1].Anchor
		}
		for j := range issueGroups[i].Instances {
			if j == 0 {
				issueGroups[i].Instances[j].PrevAnchor = issueGroups[i].Anchor
			} else {
				issueGroups[i].Instances[j].PrevAnchor = issueGroups[i].Instances[j-1].Anchor
			}
			if j < len(issueGroups[i].Instances)-1 {
				issueGroups[i].Instances[j].NextAnchor = issueGroups[i].Instances[j+1].Anchor
			} else if i < len(issueGroups)-1 {
				issueGroups[i].Instances[j].NextAnchor = issueGroups[i+1].Anchor
			}
		}
	}

	generatedAt := time.Now().UTC().Format("Mon Jan 02 15:04:05 MST 2006")

	return TemplateData{
		GeneratedAt: generatedAt,
		TotalIssues: totalIssues,
		SummaryRows: summaryRows,
		BarRows:     barRows,
		Contents:    contents,
		IssueGroups: issueGroups,
	}, nil
}

func buildEvidenceBlocks(evidence []ProcessedEvidence) []EvidenceBlockTemplate {
	if len(evidence) == 0 {
		return nil
	}

	flat := flattenEvidence(evidence)
	totalRequests := 0
	totalResponses := 0
	for _, ev := range flat {
		if strings.TrimSpace(ev.Request) != "" {
			totalRequests++
		}
		if strings.TrimSpace(ev.Response) != "" {
			totalResponses++
		}
	}

	requestCounter := 0
	responseCounter := 0
	blocks := make([]EvidenceBlockTemplate, 0, len(flat))
	for _, ev := range flat {
		block := EvidenceBlockTemplate{}
		if strings.TrimSpace(ev.URL) != "" {
			block.URL = ev.URL
			block.HasURL = true
		}
		if len(ev.InformationItems) > 0 {
			items := make([]string, 0, len(ev.InformationItems))
			for _, item := range ev.InformationItems {
				cleaned := strings.TrimSpace(item)
				if cleaned == "" {
					continue
				}
				escaped := html.EscapeString(cleaned)
				escaped = strings.ReplaceAll(escaped, "\r\n", "\n")
				escaped = strings.ReplaceAll(escaped, "\r", "\n")
				escaped = strings.ReplaceAll(escaped, "\n", "<br>")
				items = append(items, escaped)
			}
			if len(items) > 0 {
				block.InformationItems = items
				block.HasInformation = true
			}
		}
		if strings.TrimSpace(ev.Request) != "" {
			requestCounter++
			block.HasRequest = true
			if totalRequests > 1 {
				block.RequestTitle = fmt.Sprintf("Request %d", requestCounter)
			} else {
				block.RequestTitle = "Request"
			}
			block.Request = template.HTML(ev.Request)
		}
		if strings.TrimSpace(ev.Response) != "" {
			responseCounter++
			block.HasResponse = true
			if totalResponses > 1 {
				block.ResponseTitle = fmt.Sprintf("Response %d", responseCounter)
			} else {
				block.ResponseTitle = "Response"
			}
			block.Response = template.HTML(ev.Response)
		}
		if block.HasURL || block.HasInformation || block.HasRequest || block.HasResponse {
			blocks = append(blocks, block)
		}
	}

	return blocks
}

func flattenEvidence(evidence []ProcessedEvidence) []ProcessedEvidence {
	var result []ProcessedEvidence
	for _, ev := range evidence {
		result = append(result, ev)
		if ev.FirstEvidence != nil {
			result = append(result, flattenEvidence([]ProcessedEvidence{*ev.FirstEvidence})...)
		}
		if ev.SecondEvidence != nil {
			result = append(result, flattenEvidence([]ProcessedEvidence{*ev.SecondEvidence})...)
		}
	}
	return result
}

func chooseIssueDetail(issue Issue) template.HTML {
	if strings.TrimSpace(issue.Description) != "" {
		return toHTML(issue.Description)
	}
	if strings.TrimSpace(issue.IssueBackground) != "" {
		return toHTML(issue.IssueBackground)
	}
	return template.HTML("<em>No issue detail provided.</em>")
}

func toHTML(value string) template.HTML {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.ContainsAny(trimmed, "<>") {
		return template.HTML(trimmed)
	}
	escaped := html.EscapeString(trimmed)
	escaped = strings.ReplaceAll(escaped, "\r\n", "\n")
	escaped = strings.ReplaceAll(escaped, "\r", "\n")
	escaped = strings.ReplaceAll(escaped, "\n", "<br>")
	return template.HTML(escaped)
}

func normalizeSeverity(value string) string {
	v := strings.TrimSpace(strings.ToLower(value))
	switch v {
	case "critical":
		return "high"
	case "high", "medium", "low":
		return v
	case "information", "informational", "info":
		return "information"
	case "false positive", "false_positive", "falsepositive":
		return "false_positive"
	default:
		return "information"
	}
}

func severityClass(severity string) string {
	switch strings.TrimSpace(strings.ToLower(severity)) {
	case "critical":
		return "high"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "information", "informational", "info":
		return "info"
	case "false positive", "false_positive", "falsepositive":
		return "false_positive"
	default:
		return "info"
	}
}

func severityDisplay(severity string) string {
	class := severityClass(severity)
	switch class {
	case "high":
		if strings.EqualFold(severity, "critical") {
			return "Critical"
		}
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "info":
		return "Information"
	case "false_positive":
		return "False Positive"
	default:
		return titleCase(severity)
	}
}

func severityRank(severity string) int {
	switch severityClass(severity) {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	case "info":
		return 3
	case "false_positive":
		return 4
	default:
		return 5
	}
}

func normalizeConfidence(value string) string {
	v := strings.TrimSpace(strings.ToLower(value))
	switch v {
	case "certain", "firm", "tentative":
		return v
	case "":
		return "certain"
	default:
		return "tentative"
	}
}

func confidenceDisplay(confidence string) string {
	switch confidence {
	case "certain", "firm", "tentative":
		return titleCase(confidence)
	case "":
		return "Certain"
	default:
		return titleCase(confidence)
	}
}

func titleCase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	runes := []rune(s)
	first := strings.ToUpper(string(runes[0]))
	if len(runes) == 1 {
		return first
	}
	return first + strings.ToLower(string(runes[1:]))
}

func buildFullURL(origin, path string) string {
	o := strings.TrimSpace(origin)
	p := strings.TrimSpace(path)
	if o == "" {
		return p
	}
	if p == "" {
		return o
	}
	if strings.HasSuffix(o, "/") && strings.HasPrefix(p, "/") {
		return o + p[1:]
	}
	if !strings.HasSuffix(o, "/") && !strings.HasPrefix(p, "/") {
		return o + "/" + p
	}
	return o + p
}

func newBarSegment(severity, confidence string, count int) BarSegment {
	seg := BarSegment{Class: fmt.Sprintf("%s %s", severityClass(severity), confidence), Count: count}
	if count > 0 {
		width := int(math.Round(float64(count) * 37.5))
		if width < 1 {
			width = 1
		}
		seg.Width = width
	}
	return seg
}
