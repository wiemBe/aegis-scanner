# Aegis AI production kurulumu — Fedora / RHEL

Bu runbook, kök dizindeki `aegis-ai-prod.yml` dosyasını rootless Podman ve SELinux enforcing bir
Fedora/RHEL host üzerinde çalıştırır. Dosya tek başına dört servisi tanımlar: control plane,
sentetik lab API, özel LLM gateway ve loopback Nginx ingress. Uygulama ile dashboard image'ları
mutlaka `@sha256:` digest ile sabitlenir; host üzerinde kaynak koddan build yapılmaz.

> Bu stack varsayılan olarak yalnız sentetik `lab-api` hedefini değerlendirir. Gerçek şirket
> hedeflerini canlıya almadan önce ayrıca yetkilendirilmiş target inventory, kapsam, staging ve
> organizasyon onayları gerekir. Bu Compose dosyası bu onayların yerine geçmez.

## 1. Host ön koşulları

SELinux `Enforcing` kalmalı ve deployment ayrı, parolasız olmayan normal bir kullanıcıyla rootless
çalışmalıdır. Root veya privileged container gerekmez.

Fedora:

```bash
sudo dnf install -y podman podman-compose
```

RHEL 9:

```bash
sudo dnf install -y container-tools
podman compose version
```

`podman compose version` bir provider bulamıyorsa kurumun onayladığı Compose provider'ını (örneğin
`podman-compose`) kurun. `podman compose` kendi başına Compose motoru değildir; harici provider'a
delegasyon yapar. Provider seçimini sabitlemek için ilerideki environment dosyasında
`PODMAN_COMPOSE_PROVIDER=/usr/bin/podman-compose` kullanılır.

Deployment kullanıcısını oluşturun ve rootless UID/GID aralıklarını doğrulayın:

```bash
sudo useradd --create-home --shell /bin/bash aegis
grep '^aegis:' /etc/subuid /etc/subgid
sudo loginctl enable-linger aegis
```

`/etc/subuid` veya `/etc/subgid` kaydı yoksa sistem yöneticisi çakışmayan en az 65.536 kimliklik bir
aralık atamalıdır. Rootless Podman ortamını doğrulamak için `su` yerine kullanıcıya doğrudan SSH ile
giriş yapın ve şu komutları çalıştırın:

```bash
getenforce
podman info --format '{{.Host.Security.Rootless}} {{.Host.Security.SELinuxEnabled}}'
podman compose version
```

Beklenen sonuç rootless ve SELinux için `true true` değeridir. UI portu rootless çalışmaya uygun
olarak 1024'ten büyük olmalıdır; varsayılan `8000`'dir.

## 2. Deployment dosyaları ve secret hazırlığı

`aegis` kullanıcısı olarak:

```bash
install -d -m 0700 "$HOME/aegis-ai-prod" "$HOME/.config/aegis-ai" "$HOME/.config/systemd/user"
install -m 0644 aegis-ai-prod.yml "$HOME/aegis-ai-prod/aegis-ai-prod.yml"
install -m 0444 deploy/dashboard-nginx.conf "$HOME/aegis-ai-prod/dashboard-nginx.conf"
install -m 0644 deploy/extensions/manifest.json "$HOME/aegis-ai-prod/extensions.json"
install -m 0600 /dev/null "$HOME/.config/aegis-ai/provider-token"
```

Provider token'ını shell history'ye yazmadan kurum secret manager'ı veya güvenli bir editör ile
`$HOME/.config/aegis-ai/provider-token` dosyasına yerleştirin. Container UID 10001'in yalnız bu
dosyayı okuyabilmesi için rootless user namespace içinde sahipliği ayarlayın:

```bash
podman unshare chown 10001:10001 "$HOME/.config/aegis-ai/provider-token"
chmod 0400 "$HOME/.config/aegis-ai/provider-token"
chmod 0644 "$HOME/aegis-ai-prod/extensions.json"
chmod 0444 "$HOME/aegis-ai-prod/dashboard-nginx.conf"
```

Environment dosyası secret değeri içermez; yalnız immutable image referansları, endpoint/model ve
host dosya yollarını tutar:

```bash
install -m 0600 /dev/null "$HOME/.config/aegis-ai/prod.env"
```

`prod.env` içeriği:

```dotenv
PODMAN_COMPOSE_PROVIDER=/usr/bin/podman-compose
AEGIS_IMAGE=registry.company.tld/security/aegis@sha256:<64-kucuk-harf-hex>
AEGIS_DASHBOARD_IMAGE=registry.company.tld/mirror/nginx@sha256:<64-kucuk-harf-hex>
AEGIS_PROVIDER_BASE_URL=https://models.company.tld
AEGIS_PROVIDER_MODEL=security-model-v1
AEGIS_PROVIDER_TOKEN_SOURCE=/home/aegis/.config/aegis-ai/provider-token
AEGIS_EXTENSION_MANIFEST_SOURCE=/home/aegis/aegis-ai-prod/extensions.json
AEGIS_NGINX_CONFIG_SOURCE=/home/aegis/aegis-ai-prod/dashboard-nginx.conf
AEGIS_UI_PORT=8000
AEGIS_PROVIDER_RESPONSE_FORMAT=json_schema
AEGIS_PROVIDER_SUPPORTS_SEED=true
MODEL_TIMEOUT_SECONDS=60
MAX_COMPLETION_TOKENS=2048
MAX_RESPONSE_BYTES=131072
MAX_REQUESTS_PER_SCAN=8
MAX_ITERATIONS=6
MAX_MODEL_CALLS=6
MAX_TOKENS_PER_SCAN=80000
```

Registry kimliğini secret manager entegrasyonu veya `podman login` ile deployment kullanıcısının
rootless auth store'una yükleyin. Image tag'i değil, onaylanan digest'i kullanın.

## 3. Fail-closed doğrulama ve ilk deployment

Önce environment'i yükleyin ve Compose render'ını inceleyin:

```bash
set -a
. "$HOME/.config/aegis-ai/prod.env"
set +a
cd "$HOME/aegis-ai-prod"
podman compose -f aegis-ai-prod.yml config
```

Kaynak paket/virtualenv deployment hostunda mevcutsa ek topology preflight çalıştırın. Bu kontrol
secret dosyasını okumaz, provider'a bağlanmaz ve container başlatmaz:

```bash
python -m aegis.deploy.aegis_ai_prod_preflight --engine podman
```

Ardından image'ları çekin ve stack'i başlatın:

```bash
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml pull
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml up -d
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml ps
curl --fail --show-error http://127.0.0.1:8000/health
curl --fail --show-error http://127.0.0.1:8000/ready
```

`/health` yalnız liveness, `/ready` ise persistence ve güvenli çalışma kontrollerini doğrular.
Canlı trafik yalnız `/ready` HTTP 200 ve `"ready": true` döndükten sonra açılmalıdır. Repo
araçları mevcutsa kısa soak gate:

```bash
python -m aegis.deploy.staging_gate \
  --base-url http://127.0.0.1:8000 \
  --mode healthy \
  --samples 12 \
  --interval-seconds 5 \
  --output "$HOME/aegis-ai-prod/staging-gate.json"
```

Loglar raw request path/query kaydetmez. Operasyon sırasında:

```bash
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml logs --tail=200
podman stats --no-stream
curl --fail --show-error http://127.0.0.1:8000/metrics
```

Provider token'ı, environment dump'ı veya rendered config çıktısı merkezi loga gönderilmemelidir.

## 4. systemd ile canlı ortamda sürekli çalıştırma

`$HOME/.config/systemd/user/aegis-ai-prod.service` dosyasını oluşturun:

```ini
[Unit]
Description=Aegis AI production stack
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/aegis/aegis-ai-prod
EnvironmentFile=/home/aegis/.config/aegis-ai/prod.env
ExecStartPre=/usr/bin/podman compose -f aegis-ai-prod.yml config
ExecStart=/usr/bin/podman compose -p aegis-ai-prod -f aegis-ai-prod.yml up -d
ExecStop=/usr/bin/podman compose -p aegis-ai-prod -f aegis-ai-prod.yml down
TimeoutStartSec=0
TimeoutStopSec=90

[Install]
WantedBy=default.target
```

Aktifleştirin:

```bash
systemctl --user daemon-reload
systemctl --user enable --now aegis-ai-prod.service
systemctl --user status aegis-ai-prod.service
journalctl --user -u aegis-ai-prod.service -n 100 --no-pager
```

Compose dosyası restart policy içerir. `loginctl enable-linger aegis`, user service'in kullanıcı
oturumu kapandıktan ve host yeniden başladıktan sonra da çalışmasını sağlar.

## 5. TLS ve dış erişim

Container portunu `0.0.0.0` olarak değiştirmeyin. Dashboard yalnız
`127.0.0.1:${AEGIS_UI_PORT}` dinler. İnternet/intranet erişimi gerekiyorsa host üzerindeki kurumsal
reverse proxy veya load balancer şu kontrollerle loopback'e yönlendirmelidir:

- TLS 1.2/1.3 ve kurum sertifikası;
- SSO/mTLS veya kurumun kimlik doğrulama katmanı;
- request/body limitleri ve rate limit;
- yalnız gerekli kaynak ağlar için firewall/ACL;
- `/metrics` ve idari endpoint'ler için ayrıca erişim kısıtı.

Firewall'da yalnız reverse proxy'nin gerçek public portunu (genellikle 443/tcp) açın; 8000/tcp için
public kural eklemeyin.

## 6. Prompt, agent ve tool extension manifesti

`extensions.json` startup sırasında hem control plane hem gateway tarafından bir kez, fail-closed
olarak yüklenir. Dosya mutlak path, normal dosya, en fazla 64 KiB, symlink olmayan ve group/world
writable olmayan bir JSON olmalıdır. İçerik digest'i `/api/console/extensions` üzerinden görülebilir.

Örnek:

```json
{
  "schema_version": "aegis-extension-v1",
  "pack_id": "corp.security.prod",
  "pack_version": "1.1.0",
  "prompt_fragments": [
    {
      "id": "corp.report.language",
      "text": "Use concise Turkish prose and reference only the supplied evidence identifiers."
    }
  ],
  "agent_profiles": [
    {
      "id": "corp.report.agent",
      "display_name": "Kurumsal Rapor Agenti",
      "base_role": "REPORT_AGENT",
      "task_types": ["GENERATE_ASSESSMENT_REPORT"],
      "prompt_fragment_ids": ["corp.report.language"]
    }
  ],
  "tool_bindings": [
    {
      "id": "corp.bola.read",
      "display_name": "BOLA Read Verification",
      "capability_id": "bola_object_read_v1",
      "profile_id": "aegis-native-bola-synthetic",
      "description": "Existing deterministic read-only authorization comparison."
    }
  ]
}
```

Sınırlar bilinçli olarak katıdır:

- Prompt fragment yalnız mevcut bir role/task'e danışmanlık ekler. Sabit schema, kapsam, bütçe,
  verifier ve güvenlik kurallarını değiştiremez.
- Agent profile yeni yetkili runtime rolü yaratmaz; mevcut controller-owned role'ü isimlendirip
  özelleştirir. Tamamen yeni bir rol için typed request/response contract, controller routing ve
  testlerle yeni image gerekir.
- Tool binding komut, URL veya executable kod içermez. Yalnız immutable image içinde zaten kayıtlı
  capability/profile çiftine alias ekler. Yeni çalışan tool için adapter, capability, policy,
  deterministic verifier, isolation topology ve testler kodda eklenip yeni digest üretilmelidir.

Manifest değişikliğinden sonra iki servis aynı digest'i yüklesin diye stack'i kontrollü yeniden
oluşturun:

```bash
chmod 0644 "$HOME/aegis-ai-prod/extensions.json"
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml up -d --force-recreate control-plane llm-gateway
curl --fail http://127.0.0.1:8000/ready
curl --fail http://127.0.0.1:8000/api/console/extensions
```

## 7. Güncelleme, rollback ve durdurma

Yeni sürümde önce eski digest ve database volume snapshot'ını kaydedin. `prod.env` içindeki yalnız
image digest'lerini değiştirin, ardından:

```bash
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml pull
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml config
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml up -d
curl --fail http://127.0.0.1:8000/ready
```

Gate başarısız olursa trafik açmayın; `prod.env` içinde önceki onaylı digest'lere dönüp aynı `up -d`
komutunu çalıştırın. Database migration geriye uyumlu değilse image rollback öncesinde onaylı volume
snapshot'ını geri yükleyin. Volume'u doğrulama olmadan silmeyin.

Bakım durdurması:

```bash
systemctl --user stop aegis-ai-prod.service
```

Bu komut container ve networkleri kaldırır, `aegis-data` named volume'unu korur. Volume'u da silen
`down -v` üretim runbook'unda kullanılmamalıdır.
