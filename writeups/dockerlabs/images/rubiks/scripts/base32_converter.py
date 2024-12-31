import os


RED = "\033[33m"
RESET = "\033[0m"

print("Instalando xclip para copiar la salida al portapapeles. Una vez instalado borre esta línea")
os.system("sudo apt install xclip")

input = input(f"{RED}Escribe el comando aquí: {RESET}")
os.system(f"echo '{input}' | base32 | xclip -sel clip")

print("Copiado")
