import pytest

from netguard.scanners.sast.catalog import all_rules
from netguard.scanners.sast.engine import scan_text_with_rules
from netguard.scanners.sast.rules_jvm_dotnet import RULES as JVM_RULES
from netguard.scanners.sast.rules_scripting import RULES as SCRIPT_RULES

# (rule id, language, vulnerable line, safe line that must not trigger the rule)
CASES = [
    # Java
    ("java.sql-injection", "java", 'stmt.executeQuery("SELECT * FROM u WHERE id=" + id);', 'ps = conn.prepareStatement("SELECT * FROM u WHERE id=?");'),
    ("java.command-injection", "java", 'Runtime.getRuntime().exec("ping " + host);', 'Runtime.getRuntime().exec("ls");'),
    ("java.unsafe-deserialization", "java", "ObjectInputStream in = new ObjectInputStream(sock.getInputStream());", "JsonParser p = mapper.readTree(s);"),
    ("java.weak-hash", "java", 'MessageDigest.getInstance("MD5");', 'MessageDigest.getInstance("SHA-256");'),
    ("java.weak-cipher", "java", 'Cipher.getInstance("AES/ECB/PKCS5Padding");', 'Cipher.getInstance("AES/GCM/NoPadding");'),
    ("java.insecure-random", "java", "String sessionToken = new Random().nextInt() + \"\";", "int dice = new Random().nextInt(6);"),
    ("java.xxe", "java", "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();", "Foo f = Foo.create();"),
    ("java.trust-all-certificates", "java", "public void checkServerTrusted(X509Certificate[] c, String a) { }", "public void checkServerTrusted(X509Certificate[] c, String a) { verify(c); }"),
    ("java.path-traversal", "java", 'File f = new File(base + request.getParameter("f"));', 'File f = new File("/etc/app.conf");'),
    ("java.reflected-xss", "java", 'response.getWriter().println("Hi " + request.getParameter("n"));', 'response.getWriter().println("Hi");'),
    ("java.open-redirect", "java", 'response.sendRedirect(request.getParameter("next"));', 'response.sendRedirect("/home");'),
    ("java.spring-csrf-disabled", "java", "http.csrf().disable();", "http.csrf().and().build();"),
    ("java.spring-permit-all", "java", 'http.authorizeRequests().antMatchers("/**").permitAll();', 'http.authorizeRequests().antMatchers("/public/**").permitAll();'),
    ("java.hardcoded-credential-check", "java", 'if (password.equals("letmein")) ok();', "if (encoder.matches(password, hash)) ok();"),
    # C#
    ("cs.sql-injection", "csharp", 'var c = new SqlCommand("SELECT * FROM u WHERE n=\'" + name + "\'", conn);', 'var c = new SqlCommand("SELECT * FROM u WHERE n=@n", conn);'),
    ("cs.command-injection", "csharp", 'Process.Start("cmd", "/c " + input);', 'Process.Start("notepad.exe");'),
    ("cs.unsafe-deserialization", "csharp", "var f = new BinaryFormatter();", "var s = new DataContractSerializer(typeof(Foo));"),
    ("cs.weak-hash", "csharp", "using var h = MD5.Create();", "using var h = SHA256.Create();"),
    ("cs.tls-verification-disabled", "csharp", "handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;", "handler.CheckCertificateRevocationList = true;"),
    ("cs.path-traversal", "csharp", 'var t = File.ReadAllText(Request.Query["file"]);', 'var t = File.ReadAllText("config.json");'),
    ("cs.xxe", "csharp", "settings.DtdProcessing = DtdProcessing.Parse;", "settings.DtdProcessing = DtdProcessing.Prohibit;"),
    ("cs.request-validation-disabled", "csharp", "[ValidateInput(false)]", "[ValidateAntiForgeryToken]"),
    ("cs.insecure-random", "csharp", "var passwordSalt = new Random().Next();", "var n = new Random().Next(6);"),
    # Go
    ("go.sql-injection", "go", 'db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", id))', 'db.Query("SELECT * FROM u WHERE id = $1", id)'),
    ("go.command-injection", "go", 'exec.Command("sh", "-c", userCmd)', 'exec.Command("ls", dir)'),
    ("go.tls-verification-disabled", "go", "&tls.Config{InsecureSkipVerify: true}", "&tls.Config{MinVersion: tls.VersionTLS12}"),
    ("go.weak-hash", "go", "h := md5.New()", "h := sha256.New()"),
    ("go.insecure-random", "go", "sessionToken := rand.Int63()", "n := rand.Intn(6)"),
    ("go.path-traversal", "go", "data, _ := os.ReadFile(r.URL.Query().Get(\"f\"))", 'data, _ := os.ReadFile("config.yaml")'),
    ("go.ssrf", "go", 'resp, _ := http.Get(r.FormValue("url"))', 'resp, _ := http.Get("https://api.example.com")'),
    ("go.template-html", "go", "t := template.HTML(userInput)", "t := template.Must(template.New(\"a\").Parse(s))"),
    # PHP
    ("php.eval", "php", "eval($code);", "eval('return 1;');"),
    ("php.command-injection", "php", "system($_GET['cmd']);", "echo 'system update';"),
    ("php.sql-injection", "php", 'mysqli_query($c, "SELECT * FROM u WHERE id=" . $_GET["id"]);', '$stmt = $pdo->prepare("SELECT * FROM u WHERE id = ?");'),
    ("php.file-inclusion", "php", "include($_GET['page'] . '.php');", "include 'header.php';"),
    ("php.unserialize", "php", "$o = unserialize($data);", "$o = json_decode($data);"),
    ("php.reflected-xss", "php", "echo $_GET['name'];", "echo htmlspecialchars($_GET['name']);"),
    ("php.weak-hash", "php", "$h = md5($password);", "$h = password_hash($password, PASSWORD_DEFAULT);"),
    ("php.path-traversal", "php", "$d = file_get_contents($_GET['f']);", "$d = file_get_contents('a.txt');"),
    ("php.extract-request", "php", "extract($_POST);", "$name = $_POST['name'] ?? '';"),
    ("php.open-redirect", "php", "header('Location: ' . $_GET['next']);", "header('Location: /home');"),
    ("php.tls-verification-disabled", "php", "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);", "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);"),
    # Ruby
    ("rb.eval", "ruby", "eval(params[:code])", "eval('1 + 1')"),
    ("rb.command-injection", "ruby", 'system("ping #{host}")', "system('ping', host)"),
    ("rb.sql-injection", "ruby", 'User.where("name = \'#{name}\'")', 'User.where("name = ?", name)'),
    ("rb.unsafe-deserialization", "ruby", "obj = Marshal.load(data)", "obj = YAML.safe_load(data)"),
    ("rb.html-safe", "ruby", "@comment.body.html_safe", "@comment.body"),
    ("rb.mass-assignment", "ruby", "User.new(params.permit!)", "User.new(params.permit(:name))"),
    ("rb.open-redirect", "ruby", "redirect_to params[:next]", "redirect_to root_path"),
    ("rb.path-traversal", "ruby", "File.read(params[:file])", "File.read('config.yml')"),
    ("rb.weak-hash", "ruby", "Digest::MD5.hexdigest(s)", "Digest::SHA256.hexdigest(s)"),
    ("rb.csrf-skipped", "ruby", "skip_before_action :verify_authenticity_token", "before_action :authenticate"),
    ("rb.tls-verification-disabled", "ruby", "http.verify_mode = OpenSSL::SSL::VERIFY_NONE", "http.verify_mode = OpenSSL::SSL::VERIFY_PEER"),
    # Shell
    ("sh.curl-pipe-shell", "shell", "curl -sSL https://example.com/install.sh | sudo bash", "curl -sSL https://example.com/a.tar.gz -o a.tgz"),
    ("sh.chmod-777", "shell", "chmod -R 777 /var/www", "chmod 750 /var/www"),
    ("sh.eval-variable", "shell", 'eval "$USER_INPUT"', 'echo "$USER_INPUT"'),
    ("sh.tls-verification-disabled", "shell", "curl -k https://internal/x", "curl https://internal/x"),
]


@pytest.mark.parametrize("rule_id,lang,bad,good", CASES, ids=[f"{c[0]}:{i}" for i, c in enumerate(CASES)])
def test_rule_detects_vulnerable_and_ignores_safe(rule_id, lang, bad, good):
    rules = all_rules()
    hit = {f.rule_id for f in scan_text_with_rules(rules, "f", lang, bad)}
    assert rule_id in hit, f"{rule_id} missed: {bad}"
    miss = {f.rule_id for f in scan_text_with_rules(rules, "f", lang, good)}
    assert rule_id not in miss, f"{rule_id} false positive: {good}"


def test_every_rule_in_these_packs_has_a_test_case():
    assert {c[0] for c in CASES} == {r.id for r in [*JVM_RULES, *SCRIPT_RULES]}


def test_kotlin_shares_java_rules():
    findings = scan_text_with_rules(all_rules(), "A.kt", "kotlin", 'MessageDigest.getInstance("MD5")')
    assert [f.rule_id for f in findings] == ["java.weak-hash"]


def test_rule_ids_are_namespaced_and_metadata_valid():
    for rule in all_rules():
        assert "." in rule.id
        assert rule.cwe.startswith("CWE-") and rule.languages
        assert rule.severity and rule.confidence
