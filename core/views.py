# core/views.py

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import subprocess
import requests
import re
import os
import tempfile # Importado para criar arquivos temporários
import shutil # Importado para remover diretórios temporários

def index(request):
    """
    Renderiza a página inicial da aplicação de gerenciamento de riscos.
    """
    return render(request, 'core/index.html')

@csrf_exempt # Apenas para fins de teste. Em produção, use CSRF protection adequada.
def sca_scan(request):
    """
    Recebe um link do GitHub, baixa o arquivo, salva em disco temporariamente e executa uma análise SCA com Trivy.
    Retorna as vulnerabilidades encontradas pelo Trivy em formato JSON.
    """
    if request.method == 'POST':
        temp_dir_path = None # Inicializa como None para garantir que o bloco finally possa acessá-lo
        temp_file_path = None # Inicializa para clareza

        try:
            # 1. Carregar dados da requisição
            try:
                data = json.loads(request.body)
                github_url = data.get('github_url')
                if not github_url:
                    return JsonResponse({'status': 'error', 'message': 'URL do GitHub não fornecida.'}, status=400)
            except json.JSONDecodeError:
                return JsonResponse({'status': 'error', 'message': 'Formato JSON inválido na requisição.'}, status=400)

            # 2. Criar um diretório temporário para salvar o arquivo
            temp_dir_path = tempfile.mkdtemp()
            import random
            import string

            # Define o comprimento aleatório entre 1 e 100
            comprimento = random.randint(1, 100)

            # Gera o nome aleatório
            nome_aleatorio = ''.join(random.choices(string.ascii_letters, k=comprimento))

            import os
            os.system(f"mkdir tmp/tmp{nome_aleatorio}/")
            
            
            # Extrair o nome do arquivo da URL e sanitizá-lo para evitar problemas de caminho
            nome_arquivo_original = github_url.split("/")[-1]
            nome_arquivo_sanitizado = re.sub(r'[^\w\.-]', '_', nome_arquivo_original) # Remove caracteres inválidos
            temp_file_path = os.path.join(temp_dir_path, nome_arquivo_sanitizado)

            # 3. Baixar o arquivo do GitHub
            try:
                response = requests.get(github_url)
                response.raise_for_status() # Lança exceção para erros HTTP (4xx ou 5xx)
                file_content = response.text
            except requests.exceptions.MissingSchema:
                return JsonResponse({'status': 'error', 'message': 'URL do GitHub inválida. Certifique-se de que começa com http:// ou https://.'}, status=400)
            except requests.exceptions.ConnectionError:
                return JsonResponse({'status': 'error', 'message': 'Erro de conexão ao tentar baixar o arquivo do GitHub. Verifique a URL ou sua conexão de rede.'}, status=500)
            except requests.exceptions.Timeout:
                return JsonResponse({'status': 'error', 'message': 'Tempo limite excedido ao baixar o arquivo do GitHub.'}, status=500)
            except requests.exceptions.RequestException as e:
                return JsonResponse({'status': 'error', 'message': f'Erro ao baixar o arquivo do GitHub: {e}'}, status=500)

            # 4. Salvar o conteúdo no arquivo temporário
            try:
                with open(f"tmp/tmp{nome_aleatorio}/"+nome_arquivo_original , 'w', encoding='utf-8') as f:
                    f.write(file_content)
            except IOError as e:
                return JsonResponse({'status': 'error', 'message': f'Erro de E/S ao salvar o arquivo temporário: {e}'}, status=500)

            # 5. Executar a análise SCA com Trivy
            print("trivy")
            print(temp_file_path)
            
            trivy_command = [
                'trivy',
                'fs',
                '--format', 'json', # Formato de saída JSON
                f"tmp/tmp{nome_aleatorio}/"+nome_arquivo_original # Caminho para o arquivo temporário
            ]
            print(trivy_command)
            try:
                result = subprocess.run(trivy_command, capture_output=True, text=True, check=True)

                trivy_output_str = result.stdout
                print(trivy_output_str)
                trivy_error = result.stderr
               

                # Verificar se o Trivy retornou algum erro no stderr ou um código de saída diferente de zero
                if result.returncode != 0:
                    # Se houver erro no stderr, priorize-o
                    if "No vulnerabilities found" in trivy_output_str:
                         # Trivy pode retornar código de saída 1 mesmo quando não há vulnerabilidades,
                         # mas a saída indica "No vulnerabilities found".
                         # Tratamos isso como sucesso para o frontend.
                         return JsonResponse({'status': 'success', 'message': 'Análise SCA concluída. Nenhuma vulnerabilidade encontrada.', 'results': []})
                    else:
                        # Caso contrário, houve um erro real na execução do Trivy
                        error_message = trivy_error if trivy_error else f'Trivy retornou código de saída {result.returncode}.'
                        return JsonResponse({'status': 'error', 'message': f'Erro na execução do Trivy: {error_message}'}, status=500)

                # Tentar carregar a saída JSON do Trivy
                try:
                    trivy_json_output = json.loads(trivy_output_str)
                except json.JSONDecodeError as e:
                    # Isso pode acontecer se Trivy falhar e não produzir JSON válido
                    return JsonResponse({'status': 'error', 'message': f'Saída do Trivy não é um JSON válido: {e}. Saída: {trivy_output_str[:500]}'}, status=500)

                # resultar a saída do Trivy para extrair vulnerabilidades
                vulnerabilities = []
                # O formato de saída do Trivy pode variar. Geralmente, as vulnerabilidades estão em 'Results'.
                for result in trivy_json_output.get('Results', []):
                    for vulnerability in result.get('Vulnerabilities', []):
                        vulnerabilities.append({
                            'VulnerabilityID': vulnerability.get('VulnerabilityID', 'N/A'),
                            'PkgName': vulnerability.get('PkgName', 'N/A'),
                            'InstalledVersion': vulnerability.get('InstalledVersion', 'N/A'),
                            'FixedVersion': vulnerability.get('FixedVersion', 'N/A'),
                            'Severity': vulnerability.get('Severity', 'N/A'),
                            'Description': vulnerability.get('Description', 'N/A'),
                            'PrimaryURL': vulnerability.get('PrimaryURL', 'N/A'),
                        })
                
                # Retornar as vulnerabilidades encontradas
                return JsonResponse({'status': 'success', 'message': 'Análise SCA concluída com sucesso.', 'results': vulnerabilities})

            except FileNotFoundError:
                return JsonResponse({'status': 'error', 'message': 'Comando Trivy não encontrado. Certifique-se de que o Trivy está instalado e no PATH.'}, status=500)
            except subprocess.CalledresultError as e:
                return JsonResponse({'status': 'error', 'message': f'Erro ao executar o Trivy: {e.stderr}'}, status=500)
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': f'Ocorreu um erro inesperado durante a execução do Trivy: {e}'}, status=500)

        except Exception as e:
            # Captura qualquer outra exceção inesperada
            return JsonResponse({'status': 'error', 'message': f'Ocorreu um erro inesperado no servidor: {e}'}, status=500)
        finally:
            # Garante que o diretório temporário seja removido, mesmo que ocorra um erro
            if temp_dir_path and os.path.exists(temp_dir_path):
                try:
                    shutil.rmtree(temp_dir_path)
                    print(f"Diretório temporário removido: {temp_dir_path}")
                except OSError as e:
                    print(f"Erro ao remover o diretório temporário {temp_dir_path}: {e}")
    
    # Se a requisição não for POST, retorna um método não permitido
    return JsonResponse({'status': 'error', 'message': 'Método não permitido.'}, status=405)

def dast_scan(request):
    pass