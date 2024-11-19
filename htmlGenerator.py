def gerar_html(lista_itens):
    # Estrutura básica do HTML
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Historico de Navegação</title>
    </head>
    <body>
        <ul>
            {itens}
        </ul>
    </body>
    </html>
    """
    # Gerar as tags <li>
    tags_li = ""
    for data, hora, ip, href in lista_itens:
        tags_li += f'<li>{data} {hora} - {ip} - <a href="{href}">{href}</a></li>\n'

    # Substituir o placeholder com as tags <li>
    html = html_template.format(itens=tags_li)
    
    return html

# Recebe uma lista com os dados no formato (data, hora, ip, href)
#    lista_itens = [
#     ("03/11/2024", "22:24", "192.168.25.21", "http://www.pucrs.br/facin/agenda/"),
#     ("05/11/2024", "10:15", "192.168.10.15", "http://www.example.com"),
#    ]
def historicoHTML(lista_itens):

    # Gerar o HTML
    html = gerar_html(lista_itens)

    # Salvar em um arquivo
    with open("historico.html", "w", encoding="utf-8") as arquivo:
        arquivo.write(html)

    print("Arquivo HTML gerado: historico.html")

# TODO: enviar lista com parâmetros necessários ao final da etapa