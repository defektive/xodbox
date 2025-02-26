package util

import "text/template"

func CreateTemplate(name, t string) *template.Template {
	return template.Must(template.New(name).Parse(t))
}
