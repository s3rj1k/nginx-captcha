package main

const captchaHTMLTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"/>
    <title>CAPTCHA</title>
    <style>
      * {
        box-sizing: border-box;
      }
      .container {
        margin: auto;
        max-width: 320px;
      }
      .container h2 {
        text-align: center;
      }
      form.captcha input[type="text"] {
        text-align: center;
        padding: 10px;
        font-size: 17px;
        border: 1px solid grey;
        float: left;
        width: 74%;
        background: #f1f1f1;
      }
      form.captcha button {
        float: left;
        width: 26%;
        padding: 10px;
        background: #2196F3;
        color: white;
        font-size: 17px;
        border: 1px solid grey;
        border-left: none;
        cursor: pointer;
      }
      form.captcha button:hover {
        background: #0b7dda;
      }
      form.captcha::after {
        content: "";
        clear: both;
        display: table;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h2>CAPTCHA</h2>
      <p>Please verify that you are not a robot.</p>
      <img src="data:image/png;base64, {{ .Base64 }}" alt="{{ .TextHash }}" />
      <form id="captchaForm" class="captcha" method="POST" action="/">
        <input type="hidden" name="{{ .ChallengeInputName }}" value="{{ .TextHash }}">
        <input type="text" name="{{ .ResponceInputName }}" minlength="6" maxlength="6" pattern="[A-Za-z0-9]{6}" value="" autocomplete="off" autofocus>
        <button type="submit">VERIFY</button>
      </form>
      <script defer>
        document.getElementById('captchaForm').addEventListener('submit', function(event){
          event.preventDefault();
          var xhr = new XMLHttpRequest();
          var data = new FormData(this);
          xhr.open('POST', '/', true);
          xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
          xhr.send(data);
          this.submit();
        });
      </script>
    </div>
  </body>
</html>
`
