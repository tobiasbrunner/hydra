package oauth2

const consentTemplate = `
<!DOCTYPE html>
<html lang="{{.Locale}}">
<head>
    <meta charset="UTF-8">
    <title>Authorize Application {{.Client.Name}}</title>
    <style>
        html, body {
            margin: 0;
            padding: 0;
        }
    </style>
</head>
<body>
<div>
    <h1>Authorize Application</h1>
    <p>Grant application {{.Client.Name}} by {{.Client.Owner}} access to your data.</p>
    <form method="post">
        <ul>
        {{range .Scopes}}
            <li>
                <input type="checkbox" id="scope_{{.ID}}" name="scopes[]" value="{{.ID}}">
                <label for="scope_{{.ID}}"><h3>{{.Title}}</h3></label>
                <p>{{.Description}}</p>
            </li>
        {{end}}
        </ul>
        <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
        <button type="submit" name="authorization" value="grant">Authorize application</button>
        <button type="submit" name="authorization" value="reject">Deny authorization</button>
    </form>
</div>
</body>
</html>
`
