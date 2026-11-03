package main

import (
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
)

func renderRulesTab(w http.ResponseWriter, currentTab, msg, editIdxStr string) {
	renderHeader(w, currentTab, msg)
	_, ac, _ := readConfigFile()
	editIdx := -1
	editRule := AccessControlRule{Policy: "two_factor"}
	isEdit := false
	if editIdxStr != "" {
		if idx, err := strconv.Atoi(editIdxStr); err == nil && idx >= 0 && idx < len(ac.Rules) {
			editIdx = idx
			editRule = ac.Rules[idx]
			isEdit = true
		}
	}
	title := "Add Access Control Rule"
	btn := "Add"
	if isEdit {
		title = fmt.Sprintf("Edit Rule #%d", editIdx+1)
		btn = "Save"
	}

	fmt.Fprintf(w, `
<h2>Access Control Rules (<code>%s</code>)</h2>
<p style="color:#555;">Evaluated top-to-bottom. Default policy: <strong>%s</strong>.</p>
<fieldset>
  <legend>%s</legend>
  <form action="/rules/save" method="POST">
    <input type="hidden" name="index" value="%d">
    <div class="form-row"><label>Domain(s):</label><input type="text" name="domain" value="%s" required style="width:300px;" placeholder="app.example.com"></div>
    <div class="form-row"><label>Policy:</label><select name="policy">
      <option value="bypass" %s>bypass</option>
      <option value="one_factor" %s>one_factor</option>
      <option value="two_factor" %s>two_factor</option>
      <option value="deny" %s>deny</option>
    </select></div>
    <div class="form-row"><label>Subject:</label><input type="text" name="subject" value="%s" style="width:300px;" placeholder="group:admins"></div>
    <div class="form-row"><label>Networks:</label><input type="text" name="networks" value="%s" style="width:300px;" placeholder="192.168.1.0/24"></div>
    <div class="form-row"><label>Resources:</label><input type="text" name="resources" value="%s" style="width:300px;" placeholder="^/admin.*"></div>
    <div class="form-row"><label></label><button type="submit" class="btn-primary">%s</button> %s</div>
  </form>
</fieldset>
<table>
  <thead><tr><th>#</th><th>Domain(s)</th><th>Policy</th><th>Subject</th><th>Networks</th><th>Actions</th></tr></thead>
  <tbody>`,
		html.EscapeString(configPath), html.EscapeString(ac.DefaultPolicy), title, editIdx,
		html.EscapeString(fmtVal(editRule.Domain, editRule.Domains)),
		sel(editRule.Policy == "bypass"), sel(editRule.Policy == "one_factor"),
		sel(editRule.Policy == "two_factor"), sel(editRule.Policy == "deny"),
		html.EscapeString(fmtVal(editRule.Subject, nil)),
		html.EscapeString(fmtVal(editRule.Networks, nil)),
		btn, cancelLink(isEdit, "/?tab=rules"),
	)

	for i, r := range ac.Rules {
		upDis := ""
		if i == 0 {
			upDis = "disabled"
		}
		downDis := ""
		if i == len(ac.Rules)-1 {
			downDis = "disabled"
		}
		fmt.Fprintf(w, `<tr><td>%d</td><td><code>%s</code></td><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>
<form action="/rules/move" method="POST" style="display:inline;"><input type="hidden" name="index" value="%d"><input type="hidden" name="direction" value="up"><button type="submit" style="font-size:11px;" %s>&uarr;</button></form>
<form action="/rules/move" method="POST" style="display:inline;"><input type="hidden" name="index" value="%d"><input type="hidden" name="direction" value="down"><button type="submit" style="font-size:11px;" %s>&darr;</button></form>
| <a href="/?tab=rules&edit=%d">Edit</a>
| <form action="/rules/delete" method="POST" style="display:inline;" onsubmit="return confirm('Delete rule #%d?');"><input type="hidden" name="index" value="%d"><button type="submit" class="btn-danger" style="font-size:11px;">Del</button></form>
</td></tr>`,
			i+1, html.EscapeString(fmtVal(r.Domain, r.Domains)), html.EscapeString(r.Policy),
			html.EscapeString(fmtVal(r.Subject, nil)), html.EscapeString(fmtVal(r.Networks, nil)),
			i, upDis, i, downDis, i, i+1, i,
		)
	}
	if len(ac.Rules) == 0 {
		fmt.Fprintf(w, `<tr><td colspan="6" style="text-align:center;color:#666;">No rules defined.</td></tr>`)
	}
	fmt.Fprintf(w, `</tbody></table>`)
	renderFooter(w)
}

func sel(c bool) string {
	if c {
		return "selected"
	}
	return ""
}

func fmtVal(v1, v2 interface{}) string {
	v := v1
	if v == nil {
		v = v2
	}
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []interface{}:
		var s []string
		for _, x := range val {
			s = append(s, fmt.Sprintf("%v", x))
		}
		return strings.Join(s, ", ")
	case []string:
		return strings.Join(val, ", ")
	default:
		return fmt.Sprintf("%v", val)
	}
}
