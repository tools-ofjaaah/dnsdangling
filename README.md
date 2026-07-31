<!-- github-classic-token-clone:start -->
## Baixar este repositório usando um token GitHub

### 1. Criar um Personal Access Token Classic

1. No GitHub, abra **Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)**.
2. Clique em **Generate new token** → **Generate new token (classic)**.
3. Informe um nome, defina uma data de expiração e selecione o escopo **`repo`** para acessar repositórios privados.
4. Gere o token e copie-o imediatamente. O GitHub não mostrará o valor novamente.
5. Se a organização usar SAML SSO, abra **Configure SSO** ao lado do token e autorize a organização `tools-ofjaaah`.

> Nunca publique ou faça commit do token. Use apenas placeholders nos comandos e revogue o token quando ele não for mais necessário.

### 2. Clonar o repositório

Forma recomendada, sem colocar o token no comando:

```bash
git clone https://github.com/tools-ofjaaah/dnsdangling.git
```

Quando solicitado, informe seu usuário do GitHub em **Username** e o token em **Password**.

Forma direta, substituindo os placeholders:

```bash
git clone https://SEU_USUARIO:SEU_TOKEN@github.com/tools-ofjaaah/dnsdangling.git
cd dnsdangling
```

> A forma direta pode deixar o token no histórico do terminal e no arquivo `.git/config`. Depois do clone, remova-o da URL salva:

```bash
git remote set-url origin https://github.com/tools-ofjaaah/dnsdangling.git
```

Para revogar o token, acesse **Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)** e clique em **Delete**.
<!-- github-classic-token-clone:end -->

---

# dnsdangling

**DNS Dangling Scanner** - Detecta e explora vulnerabilidades de Subdomain Takeover

![DNS Dangling Scanner](assets/dnsdangle.svg)

## ⚡ Features

- 🔍 **Auto-Detection** - Enumera subdomínios e detecta CNAMEs dangling
- 🚀 **Auto-Exploit** - Cria buckets e configura políticas públicas automaticamente
- 📊 **Multiple Cloud Services** - Suporta AWS S3, Azure, GitHub Pages, Heroku, Netlify, Vercel, e mais...
- 📝 **Report Generation** - Saída em JSON para integração com outros tools
- 🎨 **Beautiful CLI** - Cores e emojis no terminal
- 🛡️ **CVSS Scoring** - Classificação de severidade automática

## 🔧 Installation

```bash
# Clone o repositório
git clone https://github.com/tools-ofjaaah/dnsdangling.git
cd dnsdangling

# Instale as dependências
pip install -r requirements.txt
```

## 📋 Requirements

```
dnspython>=2.4.0
aiohttp>=3.9.0
boto3>=1.34.0
colorama>=0.4.6
PyYAML>=6.0
```

## 🚀 Usage

```bash
# Scan básico
python3 dnsdangle_exploit.py sony.com

# Com output JSON
python3 dnsdangle_exploit.py example.com -o report.json

# Com wordlist customizada
python3 dnsdangle_exploit.py target.com -w wordlist.txt

# Ver ajuda completa
python3 dnsdangle_exploit.py --help
```

### Argumentos

| Argumento | Descrição |
|-----------|-----------|
| `domain` | Domínio alvo para scan |
| `-o, --output` | Salva resultado em JSON |
| `-w, --wordlist` | Wordlist de subdomínios customizada |
| `--region` | Região AWS (default: us-east-1) |
| `--subs` | Arquivo com lista de subdomínios |

## 🎯 Como Funciona

```
1. Enumeração de Subdomínios
   └─> Usa DNS resolution para encontrar CNAMEs

2. Detecção de Dangling
   └─> Verifica se o recurso cloud foi deletado mas DNS ainda aponta

3. Validação HTTP
   └─> Confirma vulnerabilidade via resposta HTTP (404 NoSuchBucket)

4. Exploitation (opcional)
   └─> Cria bucket na conta do atacante
   └─> Desabilita Block Public Access
   └─> Aplica bucket policy pública
   └─> Upload página de prova (PoC)
```

## 💻 Exemplo de Output

```
╔═══════════════════════════════════════════════════════════════════╗
║        OFJAAAH TAKEOVER - DNS DANGLING SCANNER v2.0         ║
║        Auto-Detect + Auto-Exploit + Index Page              ║
╚═══════════════════════════════════════════════════════════════════╝

[*] Iniciando scan em sony.com...

[*] Testando: old-api.sony.com
[!!] Encontrado CNAME para S3: old-api.sony.com.s3.amazonaws.com
[+] Bucket NAO EXISTE - VULNERAVEL!

[*] Tentando explorar (takeover)...
[+] Bucket created!
[+] Block public access disabled on bucket
[+] Public bucket policy applied
[!!!] EXPLOIT SUCCESSFUL!
[!!!] Pagina de exploits: https://old-api.sony.com.s3.amazonaws.com/index.html
```

## 🔐 AWS Credentials

O scanner busca credenciais na seguinte ordem:

1. **Variáveis de ambiente**
   ```bash
   export AWS_ACCESS_KEY_ID="AKIA..."
   export AWS_SECRET_ACCESS_KEY="..."
   export AWS_DEFAULT_REGION="us-east-1"
   ```

2. **~/.bashrc**
   ```bash
   export AWS_ACCESS_KEY_ID="AKIA..."
   export AWS_SECRET_ACCESS_KEY="..."
   ```

3. **~/.aws/credentials** (padrão AWS CLI)

## ☁️ Serviços Suportados

| Serviço | Padrão CNAME | Validação |
|---------|-------------|-----------|
| AWS S3 | `*.s3.amazonaws.com` | 404 NoSuchBucket |
| AWS CloudFront | `*.cloudfront.net` | 403/404 |
| Azure Blob | `*.blob.core.windows.net` | 400 InvalidURI |
| GitHub Pages | `*.github.io` | 404 Page not found |
| Heroku | `*.herokuapp.com` | 503/404 |
| Shopify | `*.myshopify.com` | 200 "unavailable" |
| GitLab Pages | `*.gitlab.io` | 404 |
| Netlify | `*.netlify.app` | 404 |
| Vercel | `*.vercel.app` | 404 |
| Cloudflare Pages | `*.pages.dev` | 404 |

## 📊 CVSS Scoring

Cada vulnerabilidade é classificada com CVSS 3.1:

| Severity | Score | Description |
|----------|-------|-------------|
| Critical | 9.0-10.0 | S3 público com dados sensíveis |
| High | 8.1-8.9 | Subdomain takeover com alto impacto |
| Medium | 6.0-8.0 | CDNs e serviços menores |
| Low | 3.0-5.9 | Serviços internos |

## ⚠️ Legal Disclaimer

**IMPORTANTE**: Este tool é destinado para **authorized security assessments** apenas. O uso não autorizado é proibido e pode violar leis de computador.

## 📄 License

MIT License - See LICENSE file for details.

---

**OFJAAAH Takeover** - DNS Dangling Scanner v2.0
Bug Bounty Tools by [@ofjaaah](https://github.com/ofjaaah)
