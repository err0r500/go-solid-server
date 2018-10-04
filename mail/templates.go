package mail

func AccountRecovery() string {
	return `<p>Hello,</p>
<p>We have a received a request to recover you account, originating from <strong>{{.IP}}</strong>. Please ignore this email if you did not send this request.</p>
<p>Click the following link to recover your account: <a href="{{.Link}}" target="_blank">{{.Link}}</a></p>
<p>This email was generated automatically. No one will respond if you reply to it.</p>
<p>Sincerely,
<p>{{.Host}} team</p>
`
}

func Welcome() string {
	return `<p>Hi there {{.Name}}!</p>
<br>
<p>It looks like you have successfully created your Solid account on {{.Host}}. Congratulations!</p>
<p>Your WebID (identifier) is: {{.WebID}}.</p>
<p>You can start browsing your files here: {{.Account}}.</p>
<p>We would like to reassure you that we will not use your email address for any other purpose than allowing you to authenticate and/or recover your account credentials.</p>
<p>Best,</p>
<p>{{.Host}} team</p>
`
}
