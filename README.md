# Ondaweb Security Updater

Plugin WordPress da [Ondaweb](https://ondaweb.com.br) para manutenção de sites de clientes (simples ou multisite):

- Inventário de versões do WordPress, plugins e temas, com classificação gratuito / licença Ondaweb / pago / personalizado
- Histórico automático de atualizações (painel, automáticas, WP-CLI e FTP)
- Verificações e correções de segurança com nota de A a E
- Vulnerabilidades conhecidas (Wordfence Intelligence)
- Endereço de login personalizado e reCAPTCHA v2/v3
- Relatório mensal por e-mail e PDF para o cliente

## Instalação

Baixe o arquivo **ondaweb-update-manager.zip** da [última versão](../../releases/latest) e envie em **Plugins → Adicionar novo → Enviar plugin** (em multisite: ative na rede).

Depois de instalado, as novas versões aparecem na tela de Plugins do WordPress.

## Publicar uma nova versão

1. Altere o número da versão em `ondaweb-update-manager.php` (cabeçalho `Version:` **e** a constante `OWUM_VERSION`).
2. Descreva as mudanças em `CHANGELOG.md`, numa seção `## X.Y.Z`.
3. Envie para a branch `main`.

A automação em `.github/workflows/release.yml` percebe o número novo, confere a sintaxe PHP, monta o `.zip` e publica a release `vX.Y.Z`. Envios sem mudança de versão não publicam nada. Os sites recebem a atualização em até 12 horas (ou na hora, em **Ondaweb Security → Atualizações → Verificar atualizações agora**).

> A pasta dentro do `.zip` se chama `ondaweb-update-manager` — não altere, pois é ela que mantém o histórico e as configurações nos sites.

## Recuperação de acesso

No `wp-config.php`:

```php
define( 'OWSU_LOGIN_SLUG_OFF', true ); // volta o login para /wp-login.php
define( 'OWSU_RECAPTCHA_OFF', true );  // desliga o reCAPTCHA
```
