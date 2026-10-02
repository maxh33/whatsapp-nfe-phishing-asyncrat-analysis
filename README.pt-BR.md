# Golpe da nota fiscal falsa (NF-e) no WhatsApp: análise do vírus AsyncRAT

Análise de um golpe real contra lojas virtuais brasileiras: um **falso cliente no WhatsApp Business** reclama de "pedido duplicado" e manda a "nota fiscal" `NFE_…_PDF.js`. **Não é PDF nem nota fiscal**: é um **vírus para Windows** (trojan de acesso remoto **AsyncRAT**) que dá ao golpista controle total do computador e mostra uma **tela falsa de "Windows Update"** enquanto ele mexe no banco da vítima.

🇺🇸 Technical analysis in English: [README.md](README.md)

> Este repositório **não contém o vírus**. Só a análise, os indicadores e regras de detecção.

---

## Como o golpe chega

1. Mensagem no WhatsApp da loja: *"Boa tarde, fiz uma compra com vocês e acabou que veio meus pedidos duplicados, entrei em contato com a plataforma e pediram pra mandar mensagem pra vocês arrumar o erro, junto com a nota fiscal. Paguei por 1 produto e veio 2."*
2. Logo depois chega o arquivo `NFE_7482594_0938402947928387421_PDF.js` (3,6 MB, ícone "JS").
3. Quem atende a loja pelo **WhatsApp Web no computador** e abre o arquivo é infectado na hora, sem nenhum aviso.

## O que o vírus faz

- Instala-se escondido dentro de um programa do próprio Windows e apaga os rastros em segundos.
- Conecta ao servidor do golpista (`dhdxhdhdhd[.]duckdns[.]org`, `uhdyadasud[.]duckdns[.]org`, IP `45.149.153[.]144`).
- Permite ver e controlar a tela, capturar o que é digitado e roubar senhas.
- Mostra uma **tela falsa de "Trabalhando nas atualizações. Não desligue o computador"** que trava teclado e mouse. Essa tela não aparece para o golpista, que vê a área de trabalho real e opera o internet banking ou a carteira de criptomoedas enquanto a vítima espera.

## Celular corre risco?

**Não.** O arquivo só funciona em Windows. Aberto no Android ou no iPhone, ele não faz nada (testado). Basta apagar. O risco é abrir no **computador**.

## Como reconhecer

- Nota fiscal de verdade vem em **PDF (DANFE) ou XML**. Nunca em `.js`, `.vbs`, `.hta`, `.bat`, `.exe` ou `.zip`.
- Desconfie de "PDF" no meio do nome (`_PDF.js`). O Windows esconde a extensão por padrão: ative "Extensões de nomes de arquivos" no Explorador de Arquivos.
- Desconfie de cliente que "manda a nota" para você. Quem emite a nota é a loja.
- "A plataforma pediu para falar com vocês" é usado para dar credibilidade.

## O que fazer

| Situação | Ação |
|---|---|
| Recebeu | Não abra. Apague, denuncie e bloqueie o contato no WhatsApp. |
| Abriu no celular | Apague. Não precisa formatar. |
| Abriu no computador | Tire o computador da internet na hora. Não acesse banco nele. De outro aparelho, troque as senhas e avise o banco. Chame um técnico e reinstale o Windows. |
| Tem empresa | Bloqueie os domínios e o IP acima no roteador ou firewall. Configure o Windows para abrir `.js`, `.vbs` e `.hta` no Bloco de Notas. |

## Detalhes técnicos

- [Cadeia de infecção](docs/01-infection-chain.md): JavaScript → AutoIt → shellcode Donut → .NET
- [Configuração do AsyncRAT e ChaCha20](docs/02-asyncrat-config-chacha20.md)
- [Capacidades e a tela falsa de Windows Update](docs/03-capabilities-fake-windows-update.md)
- [Detecção e resposta a incidentes](docs/04-detection-and-response.md)
- [Lições aprendidas](docs/lessons-learned.md)
- [Indicadores (IOCs)](iocs/iocs.csv) · [Regras YARA e Sigma](detection/)

## Onde denunciar

- **WhatsApp:** abrir a conversa → nome do contato → *Denunciar*.
- **CERT.br:** `cert@cert.br` (incidentes de segurança no Brasil).
- **Polícia:** boletim de ocorrência online ou na delegacia de crimes cibernéticos do seu estado.

---

Autor: **Max Haider** · [maxhaider.dev](https://maxhaider.dev). Compartilhe com quem atende clientes pelo WhatsApp.
