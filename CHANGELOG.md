# Histórico de versões

## 1.5.5
- **Servidores atrás de NAT** (IP interno como 192.168.x.x), que não alcançam o próprio endereço público ("Connection timeout"): o plugin passa a acessar o site direto pelo endereço local (127.0.0.1 ou o IP do servidor), mantendo o domínio e o certificado. As verificações de segurança voltam a funcionar sem depender do navegador.
- O mesmo desvio vale para as chamadas do próprio WordPress ao site, como o WP-Cron (rotina diária, envio dos relatórios) e a Saúde do site.
- O painel de Segurança informa quando esse desvio está em uso e, se nem assim o servidor alcançar o site, explica o que a hospedagem precisa ajustar (arquivo hosts ou NAT loopback).

## 1.5.4
- **Sites cujo servidor não consegue acessar o próprio site** (firewall, proxy ou página lenta):
  - aviso no painel de Segurança com o erro exato, o IP do servidor e o que pedir à hospedagem;
  - botão "Ler os cabeçalhos pelo meu navegador e verificar de novo": a página inicial é lida pelo navegador do administrador e os cabeçalhos de segurança passam a ser verificados mesmo assim (vale por 24 horas);
  - as correções dos itens que não puderam ser testados podem ser aplicadas mesmo assim.
- A verificação carrega a página inicial uma única vez (antes eram várias), com tempo limite maior e uma nova tentativa — menos carga e menos chance de disparar o firewall do servidor.
- Arquivos sensíveis e listagem de usuários não aparecem mais como "OK" quando o teste não pôde ser feito.

## 1.5.3
- **Frequência do relatório por e-mail** (Configurações → Relatório):
  - **Semanal:** toda segunda-feira, com a semana anterior (segunda a domingo).
  - **Quinzenal:** dias 15 e 30 (em fevereiro, no último dia do mês), com o período desde o envio anterior.
  - **Mensal (padrão):** no dia escolhido, com o mês anterior.
- A tela mostra a data do próximo relatório e o período que ele vai cobrir; os botões de "Enviar agora" acompanham a frequência escolhida.
- Se o WP-Cron atrasar, o relatório semanal ou quinzenal ainda sai em até 3 dias; envios mais antigos não se acumulam.
- Tradução que faltava no aviso de falha ao consultar o GitHub.

## 1.5.2
- **Correção:** em alguns servidores (hospedagem compartilhada), a consulta à API do GitHub atingia o limite de 60 consultas por hora por IP e a atualização do plugin não aparecia. Agora, se a API não responder, o plugin encontra a versão nova pela página pública de versões do GitHub, que não tem esse limite.
- Se mesmo assim não for possível consultar o GitHub, a tela de Atualizações mostra um aviso com o motivo e o link para baixar a versão manualmente.

## 1.5.1
- **Novo visual do painel no padrão Ondaweb:** barra com o logo da Ondaweb no topo de todas as telas, botões arredondados (ação principal em laranja), cartões de resumo e nota de segurança no estilo do relatório, tabelas com cabeçalho preto e cantos arredondados, seções de Configurações em cartões e etiquetas de situação nas cores da marca.
- Barra de progresso da verificação e item do plugin no menu lateral nas cores da Ondaweb.

## 1.5.0
- **Novo layout do relatório do cliente** (e-mail e PDF), no padrão visual da Ondaweb: capa com a nota de segurança, resumo com indicadores, "Como a verificação foi feita", as 9 áreas cobertas, cartões de "Medidas implementadas e verificadas" (ações, risco reduzido e resultado verificado), quadro geral de resultados, atualizações, inventário, datas de referência (validade do certificado HTTPS e fim do suporte do PHP) e observação final.
- No PDF, cada página tem o logo da Ondaweb no topo e rodapé com "Página X de Y" (Chrome/Edge).
- Itens ainda pendentes aparecem como "Em tratamento pela equipe Ondaweb", sem detalhes técnicos.
- **Nome e logo da Ondaweb fixos:** não podem mais ser alterados nas Configurações. O cliente continua podendo ter o próprio logo no relatório.
- **Versão internacional:** o plugin agora é escrito em inglês e traduzido para português do Brasil (arquivos em `/languages`). Sites em português continuam vendo tudo em português; sites em outros idiomas veem em inglês. Datas seguem o formato do idioma do site.
- Instalações existentes mantêm os mesmos destinatários de e-mail e o Elementor Pro como licença Ondaweb. Instalações novas começam com os e-mails do administrador do site.
- O aviso de erro do painel de Segurança não depende mais do idioma da mensagem.

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
