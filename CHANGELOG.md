# Histórico de versões

## 1.4.0
- **Verificação com barra de progresso:** a verificação de segurança mostra o andamento item a item, o tempo restante e o resultado de cada teste. Cada item roda separado, sem risco de estourar o tempo limite do servidor.
- Indicador "aguarde" nas ações demoradas (aplicar/desfazer correção, verificar atualizações, enviar relatório, salvar configurações).
- **Registro de erros:** nova tela que guarda erros fatais do site (de qualquer plugin, tema ou do WordPress), avisos deste plugin e falhas das operações, com origem, arquivo, endereço, usuário e rastreamento. Exportação em .txt.
- **Alertas por e-mail** ao desenvolvedor para erros fatais e falhas do plugin (no máximo 1 e-mail por erro a cada 6 horas).
- **Correção:** o envio do relatório por e-mail causava "erro crítico" em sites com plugins de SMTP que substituem o envio padrão do WordPress. Os logos agora são embutidos só quando possível, e qualquer falha de envio aparece como aviso.
- **Correção:** aplicar correções e verificar atualizações podiam exceder o tempo limite do servidor em sites grandes; tempos ajustados.

## 1.3.0
- **Atualizações automáticas pelo GitHub:** o plugin passa a receber novas versões pela tela de Plugins do WordPress, como qualquer outro plugin (com opção de atualização automática).
- Ícone da Ondaweb na lista de atualizações.

## 1.2.0
- **Endereço de login personalizado** (substitui o WPS Hide Login): /wp-login.php e /wp-admin passam a responder "página não encontrada" para visitantes; aviso por e-mail ao alterar.
- **reCAPTCHA v2 ou v3** no login, senha perdida e cadastro, ativado somente após teste bem-sucedido.
- Novas verificações de segurança: endereço de login e proteção anti-robô.
- Constantes de recuperação de acesso: `OWSU_LOGIN_SLUG_OFF` e `OWSU_RECAPTCHA_OFF`.

## 1.1.1
- Logo da Ondaweb incluído no plugin (sem necessidade de configurar).
- Novo tipo "Personalizado", detectado automaticamente para temas filhos.
- Textos ajustados para sites que não são multisite.

## 1.1.0
- **Módulo de segurança:** 31 verificações, nota de A a E, correções com um clique e "Desfazer".
- Vulnerabilidades conhecidas pela base Wordfence Intelligence.
- Seção de segurança no relatório do cliente (sem detalhes técnicos) e relatório técnico interno.
- Plugin renomeado para Ondaweb Security Updater.

## 1.0.3
- Filtros e ordenação por coluna no painel de atualizações.

## 1.0.2
- Logos do cliente e da Ondaweb no relatório (PDF e e-mail).

## 1.0.1
- Tipo "Licença Ondaweb" (Elementor Pro por padrão) e link "Abrir painel".

## 1.0.0
- Inventário de WordPress, plugins e temas da rede, histórico automático de atualizações, relatório mensal por e-mail e PDF.
