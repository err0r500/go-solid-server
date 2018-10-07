package pages

import "github.com/err0r500/go-solid-server/uc"

type pageTemplates struct {
	systemPrefix string
}

func New(systemPrefix string) uc.Templater {
	return pageTemplates{systemPrefix: systemPrefix}
}

func (pageTemplates) Login(...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<head>
    <link type="text/css" rel="stylesheet" href="https://solid.github.io/solid-panes/style/tabbedtab.css" />
    <script>
      var $SOLID_GLOBAL_config = {
        popupUri: window.location.origin + '/common/popup.html'
      }
    </script>
    <script type="text/javascript" src="https://linkeddata.github.io/mashlib/dist/mashlib.min.js"></script>
    <script>
      document.addEventListener('DOMContentLoaded', function () {
        const panes = require('mashlib')
        const UI = panes.UI

        // Set up cross-site proxy
        const $rdf = UI.rdf
        $rdf.Fetcher.crossSiteProxyTemplate = document.origin + '/xss/?uri={uri}'

        // Authenticate the user
        UI.authn.checkUser()
          .then(function () {
            // Set up the view for the current subject
            const kb = UI.store
            const uri = window.location.href
            const subject = kb.sym(uri)
            const outliner = panes.getOutliner(document)
            outliner.GotoSubject(subject, true, undefined, true, undefined)
          })
      })
    </script>
</head>
<body>
<div class="TabulatorOutline" id="DummyUUID">
    <table id="outline"></table>
</div>
</body>
</html>`
}

func (p pageTemplates) NewCert(...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<body>
    <form method="POST" action="/` + p.systemPrefix + `/cert">
    <h2>Issue new certificate</h2>
    Name: <input type="text" name="name">
    WebID: <input type="text" name="webid" autocorrect="off">
    <keygen id="spkacWebID" name="spkac" challenge="randomchars" keytype="rsa" hidden></keygen>
    <input type="submit" value="Issue">
    </form>
</body>
</html>`
}

func (pageTemplates) AccountRecoveryPage(...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<body>
    <h2>Recover access to your account</h2>
    <form method="POST">
    What is your WebID?
    <br>
    <input type="url" name="webid" autocorrect="off">
    <input type="submit" value="Recover account">
    </form>
</body>
</html>`
}

func (p pageTemplates) Unauthenticated(...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>401 - Unauthorized! You need to authenticate to access this resource.</h1>
    <form method="POST" action="/` + p.systemPrefix + `/login">
    <h2>Login</h2>
    WebID:
    <br>
    <input type="url" name="webid" autocorrect="off">
    <br>
    Password:
    <br>
    <input type="password" name="password">
    <br>
    <input type="submit" value="Login">
    </form>
    <p><a href="/` + p.systemPrefix + `/recovery">Forgot your password?</a></p>
    <br>
    <p>Do you need a WebID? You can sign up for one at <a href="https://databox.me/" target="_blank">databox.me</a>.</p>
</body>
</html>`
}

func (p pageTemplates) Unauthorized(...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>403 - oh noes, access denied!</h1>
    <h2>Please visit the <a href="/` + p.systemPrefix + `/accountRecovery">recovery page</a> in case you have lost access to your credentials.</h2>
</body>
</html>`
}

func (pageTemplates) NotFound(...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>404 - oh noes, there's nothing here</h1>
</body>
</html>`
}

func (p pageTemplates) NewPassTemplate(token, err string, others ...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<body>
    <form method="POST" action="/` + p.systemPrefix + `/recovery?token=` + token + `">
    <h2>Please provide a new password</h2>
    <p style="color: red;">` + err + `</p>
    Password:
    <br>
    <input type="password" name="password">
    <br>
    Password (type again to verify):
    <br>
    <input type="password" name="verifypass">
    <br>
    <input type="submit" value="Submit">
    </form>
</body>
</html>`
}

func (p pageTemplates) LoginTemplate(redir, origin, webid string, others ...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<body>
    <form method="POST" action="/` + p.systemPrefix + `/login?redirect=` + redir + `&origin=` + origin + `">
    <h2>Login</h2>
    WebID:
    <br>
    <input type="url" name="webid" value="` + webid + `" autocorrect="off">
    <br>
    Password:
    <br>
    <input type="password" name="password" autofocus>
    <br>
    <input type="submit" value="Login">
    </form>
    <p><a href="/` + p.systemPrefix + `/recovery">Forgot your password?</a></p>
    <br>
    <p>Do you need a WebID? You can sign up for one at <a href="https://databox.me/" target="_blank">databox.me</a>.</p>
</body>
</html>`
}

func (p pageTemplates) UnauthorizedTemplate(redirTo, webid string, others ...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>401 - Unauthorized! You need to authenticate to access this resource.</h1>
    <form method="POST" action="/` + p.systemPrefix + `/login?redirect=` + redirTo + `">
    <h2>Login</h2>
    WebID:
    <br>
    <input type="url" name="webid" value="` + webid + `" autocorrect="off">
    <br>
    Password:
    <br>
    <input type="password" name="password" autofocus>
    <br>
    <input type="submit" value="Login">
    </form>
    <p><a href="/` + p.systemPrefix + `/recovery">Forgot your password?</a></p>
    <br>
    <p>Do you need a WebID? You can sign up for one at <a href="https://databox.me/" target="_blank">databox.me</a>.</p>
</body>
</html>`
}

func (p pageTemplates) LogoutTemplate(webid string, other ...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>You are logged in as ` + webid + `.</h1>
    <h2><a href="/` + p.systemPrefix + `/logout">Click here to logout</a></h2>
</body>
</html>`
}

func (pageTemplates) TokensTemplate(tokens string, others ...string) string {
	return `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    ` + tokens + `
</body>
</html>`
}
