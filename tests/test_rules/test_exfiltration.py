"""Tests for scanner.rules.exfiltration — CL-*, DE-*, PX-*, ST-* rules."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import scan_text

from scanner.models import Severity
from scanner.rules.exfiltration import (
    ApiKeyLeak,
    AwsCredentialsExtraction,
    Base64SensitiveDataEncoding,
    Base64WithSendContext,
    CredentialsLeak,
    DotEnvFileLeak,
    EtcPasswdExtraction,
    GistExposure,
    HomeDirectoryLeak,
    KeychainExtraction,
    NgrokExposure,
    OsEnvironExtraction,
    PastebinExposure,
    PostmanExposure,
    PrivateKeyLeak,
    ProcessEnvExtraction,
    RequestBinExposure,
    SecretLeak,
    ShellEnvVarExtraction,
    SshKeyExtraction,
    TokenLeak,
    WebhookExposure,
    PasswordLeak,
)


# ---------------------------------------------------------------------------
# CL-001 — HomeDirectoryLeak
# ---------------------------------------------------------------------------


class TestHomeDirectoryLeak:
    def test_matches_tilde_slash(self) -> None:
        findings = scan_text(HomeDirectoryLeak, "path = ~/Documents/secret.txt")
        assert len(findings) == 1

    def test_matches_dollar_home(self) -> None:
        findings = scan_text(HomeDirectoryLeak, "export PATH=$HOME/bin:$PATH")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(HomeDirectoryLeak, "ls ~/Documents")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(HomeDirectoryLeak, "The user's home base is important.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CL-002 — DotEnvFileLeak
# ---------------------------------------------------------------------------


class TestDotEnvFileLeak:
    def test_matches_dotenv(self) -> None:
        findings = scan_text(DotEnvFileLeak, "load_dotenv('.env')")
        assert len(findings) == 1

    def test_matches_dotenv_local(self) -> None:
        findings = scan_text(DotEnvFileLeak, "cat .env.local")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(DotEnvFileLeak, "source .env")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_environment_word(self) -> None:
        findings = scan_text(DotEnvFileLeak, "Configure the environment variables in the system.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CL-003 — CredentialsLeak
# ---------------------------------------------------------------------------


class TestCredentialsLeak:
    def test_matches_credentials(self) -> None:
        findings = scan_text(CredentialsLeak, "Send the credentials to the endpoint.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(CredentialsLeak, "credentials file")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(CredentialsLeak, "Please verify your identity first.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CL-004 — TokenLeak
# ---------------------------------------------------------------------------


class TestTokenLeak:
    def test_matches_token_assignment(self) -> None:
        findings = scan_text(TokenLeak, "token = 'abc123'")
        assert len(findings) == 1

    def test_matches_api_token(self) -> None:
        findings = scan_text(TokenLeak, "api_token = os.getenv('TOKEN')")
        assert len(findings) == 1

    def test_matches_auth_token(self) -> None:
        findings = scan_text(TokenLeak, "auth_token = request.headers.get('Authorization')")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(TokenLeak, "bearer_token = secret")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(TokenLeak, "The token economy model is widely studied.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CL-005 — ApiKeyLeak
# ---------------------------------------------------------------------------


class TestApiKeyLeak:
    def test_matches_api_key(self) -> None:
        findings = scan_text(ApiKeyLeak, "api_key = 'my_secret_key'")
        assert len(findings) == 1

    def test_matches_apikey(self) -> None:
        findings = scan_text(ApiKeyLeak, "apikey=ABCDEF123456")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(ApiKeyLeak, "API_KEY=value")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(ApiKeyLeak, "Read the API documentation carefully.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CL-006 — SecretLeak
# ---------------------------------------------------------------------------


class TestSecretLeak:
    def test_matches_secret_assignment(self) -> None:
        findings = scan_text(SecretLeak, "secret = 'top_secret_value'")
        assert len(findings) == 1

    def test_matches_secret_key(self) -> None:
        findings = scan_text(SecretLeak, "secret_key = 'django-insecure-...'")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(SecretLeak, "client_secret = value")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(SecretLeak, "This feature is still a secret for now.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CL-007 — PasswordLeak
# ---------------------------------------------------------------------------


class TestPasswordLeak:
    def test_matches_password_assignment(self) -> None:
        findings = scan_text(PasswordLeak, "password = 'hunter2'")
        assert len(findings) == 1

    def test_matches_passwd(self) -> None:
        findings = scan_text(PasswordLeak, "cat /etc/passwd | grep root")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(PasswordLeak, "password='secret'")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(PasswordLeak, "Users should choose strong passwords.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CL-008 — PrivateKeyLeak
# ---------------------------------------------------------------------------


class TestPrivateKeyLeak:
    def test_matches_private_key(self) -> None:
        findings = scan_text(PrivateKeyLeak, "Load the private key from the file.")
        assert len(findings) == 1

    def test_matches_private_underscore_key(self) -> None:
        findings = scan_text(PrivateKeyLeak, "private_key = load_key('key.pem')")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(PrivateKeyLeak, "private key detected")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(PrivateKeyLeak, "The public key is used for encryption.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DE-001 — OsEnvironExtraction
# ---------------------------------------------------------------------------


class TestOsEnvironExtraction:
    def test_matches_os_environ(self) -> None:
        findings = scan_text(OsEnvironExtraction, "secrets = os.environ")
        assert len(findings) == 1

    def test_matches_os_environ_get(self) -> None:
        findings = scan_text(OsEnvironExtraction, "token = os.environ.get('API_KEY')")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(OsEnvironExtraction, "os.environ")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(OsEnvironExtraction, "Check the operating system documentation.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DE-002 — ProcessEnvExtraction
# ---------------------------------------------------------------------------


class TestProcessEnvExtraction:
    def test_matches_process_env(self) -> None:
        findings = scan_text(ProcessEnvExtraction, "const key = process.env.API_KEY")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(ProcessEnvExtraction, "process.env.SECRET")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(ProcessEnvExtraction, "The running process should be monitored.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DE-003 — ShellEnvVarExtraction
# ---------------------------------------------------------------------------


class TestShellEnvVarExtraction:
    def test_matches_dollar_env(self) -> None:
        findings = scan_text(ShellEnvVarExtraction, "echo $ENV")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(ShellEnvVarExtraction, "export X=$ENV")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(ShellEnvVarExtraction, "Set the environment variables before running.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DE-004 — EtcPasswdExtraction
# ---------------------------------------------------------------------------


class TestEtcPasswdExtraction:
    def test_matches_etc_passwd(self) -> None:
        findings = scan_text(EtcPasswdExtraction, "cat /etc/passwd")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(EtcPasswdExtraction, "Read /etc/passwd to get user list")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(EtcPasswdExtraction, "User authentication is handled by PAM.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DE-005 — KeychainExtraction
# ---------------------------------------------------------------------------


class TestKeychainExtraction:
    def test_matches_keychain(self) -> None:
        findings = scan_text(KeychainExtraction, "Read from the keychain using security tool.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(KeychainExtraction, "keychain access")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(KeychainExtraction, "A ring of keys was found at the site.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DE-006 — SshKeyExtraction
# ---------------------------------------------------------------------------


class TestSshKeyExtraction:
    def test_matches_id_rsa(self) -> None:
        findings = scan_text(SshKeyExtraction, "cat ~/.ssh/id_rsa")
        assert len(findings) == 1

    def test_matches_id_ed25519(self) -> None:
        findings = scan_text(SshKeyExtraction, "ssh-keygen -t ed25519 && cat id_ed25519")
        assert len(findings) == 1

    def test_matches_ssh_key(self) -> None:
        findings = scan_text(SshKeyExtraction, "Upload the ssh key to the server.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(SshKeyExtraction, "id_rsa found")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(SshKeyExtraction, "Secure Shell provides encrypted communication.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DE-007 — AwsCredentialsExtraction
# ---------------------------------------------------------------------------


class TestAwsCredentialsExtraction:
    def test_matches_aws_credentials(self) -> None:
        findings = scan_text(AwsCredentialsExtraction, "cat ~/.aws/credentials")
        assert len(findings) == 1

    def test_matches_dot_aws_path(self) -> None:
        findings = scan_text(AwsCredentialsExtraction, "cp keys.json .aws/config")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(AwsCredentialsExtraction, "aws_credentials file")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(AwsCredentialsExtraction, "Use AWS IAM roles for authentication.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PX-001 — WebhookExposure
# ---------------------------------------------------------------------------


class TestWebhookExposure:
    def test_matches_webhook(self) -> None:
        findings = scan_text(WebhookExposure, "POST to the webhook URL with the payload.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(WebhookExposure, "webhook endpoint configured")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(WebhookExposure, "The notification system uses an internal queue.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PX-002 — PastebinExposure
# ---------------------------------------------------------------------------


class TestPastebinExposure:
    def test_matches_pastebin(self) -> None:
        findings = scan_text(PastebinExposure, "Upload data to pastebin.com for sharing.")
        assert len(findings) == 1

    def test_matches_hastebin(self) -> None:
        findings = scan_text(PastebinExposure, "Post to hastebin for quick sharing.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(PastebinExposure, "send to pastebin.com")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(PastebinExposure, "Share via the internal documentation system.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PX-003 — GistExposure
# ---------------------------------------------------------------------------


class TestGistExposure:
    def test_matches_gist_github(self) -> None:
        findings = scan_text(GistExposure, "Upload to gist.github.com for distribution.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(GistExposure, "gist.github.com")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(GistExposure, "The gist of the matter is summarized below.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PX-004 — RequestBinExposure
# ---------------------------------------------------------------------------


class TestRequestBinExposure:
    def test_matches_requestbin(self) -> None:
        findings = scan_text(RequestBinExposure, "Post the request to requestbin for inspection.")
        assert len(findings) == 1

    def test_matches_hookbin(self) -> None:
        findings = scan_text(RequestBinExposure, "Use hookbin to capture incoming webhooks.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(RequestBinExposure, "requestbin.net/r/xxx")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(RequestBinExposure, "Inspect the HTTP request headers.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PX-005 — NgrokExposure
# ---------------------------------------------------------------------------


class TestNgrokExposure:
    def test_matches_ngrok(self) -> None:
        findings = scan_text(NgrokExposure, "Start ngrok to expose the local server.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(NgrokExposure, "ngrok http 8080")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(NgrokExposure, "Use a VPN to access the internal network.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PX-006 — PostmanExposure
# ---------------------------------------------------------------------------


class TestPostmanExposure:
    def test_matches_postman(self) -> None:
        findings = scan_text(PostmanExposure, "Forward the request via Postman for debugging.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(PostmanExposure, "postman collection")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(PostmanExposure, "Deliver mail to the relevant team.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ST-001 — Base64WithSendContext
# ---------------------------------------------------------------------------


class TestBase64WithSendContext:
    def test_matches_base64_send(self) -> None:
        findings = scan_text(Base64WithSendContext, "data = base64(payload); send(data)")
        assert len(findings) == 1

    def test_matches_base64_upload(self) -> None:
        findings = scan_text(Base64WithSendContext, "upload base64 encoded data to server")
        assert len(findings) == 1

    def test_matches_base64_post(self) -> None:
        findings = scan_text(Base64WithSendContext, "base64 encode then post to endpoint")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(Base64WithSendContext, "base64 the data then transmit it")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_base64_alone(self) -> None:
        findings = scan_text(Base64WithSendContext, "The content is base64 encoded for display.")
        assert len(findings) == 0

    def test_no_match_send_alone(self) -> None:
        findings = scan_text(Base64WithSendContext, "Please send me the document.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ST-002 — Base64SensitiveDataEncoding
# ---------------------------------------------------------------------------


class TestBase64SensitiveDataEncoding:
    def test_matches_b64encode_password(self) -> None:
        findings = scan_text(Base64SensitiveDataEncoding, "b64encode(password)")
        assert len(findings) == 1

    def test_matches_b64encode_token(self) -> None:
        findings = scan_text(Base64SensitiveDataEncoding, "base64.b64encode(token)")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(Base64SensitiveDataEncoding, "b64encode(api_key)")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(Base64SensitiveDataEncoding, "b64encode(image_data)")
        assert len(findings) == 0
