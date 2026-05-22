import nmap
import time
import csv
import threading
from concurrent.futures import ThreadPoolExecutor
from tkinter import *
from tkinter import ttk, filedialog, messagebox

# ======================================
# CONFIGURAÇÕES
# ======================================

MAX_THREADS = 50

# ======================================
# NMAP
# ======================================

scanner_nmap = nmap.PortScanner(
    nmap_search_path=(
        'C:\\Program Files (x86)\\Nmap\\nmap.exe',
        'C:\\Program Files\\Nmap\\nmap.exe'
    )
)

# ======================================
# INTERFACE
# ======================================

class ScannerGUI:

    def __init__(self, root):

        self.root = root
        self.root.title("Scanner de Portas TCP")
        self.root.geometry("1000x650")
        self.root.configure(bg="#1e1e1e")

        self.resultados = []

        # ======================================
        # TÍTULO
        # ======================================

        titulo = Label(
            root,
            text="Scanner de Portas TCP - 3 Way Handshake",
            font=("Arial", 22, "bold"),
            bg="#1e1e1e",
            fg="white"
        )

        titulo.pack(pady=15)

        # ======================================
        # TOPO
        # ======================================

        frame_top = Frame(root, bg="#1e1e1e")
        frame_top.pack(pady=10)

        Label(
            frame_top,
            text="IP:",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 12)
        ).grid(row=0, column=0, padx=5)

        self.ip_entry = Entry(frame_top, width=18, font=("Arial", 12))
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=5)

        Label(
            frame_top,
            text="Porta Inicial:",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 12)
        ).grid(row=0, column=2, padx=5)

        self.start_port = Entry(frame_top, width=10, font=("Arial", 12))
        self.start_port.insert(0, "1")
        self.start_port.grid(row=0, column=3, padx=5)

        Label(
            frame_top,
            text="Porta Final:",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 12)
        ).grid(row=0, column=4, padx=5)

        self.end_port = Entry(frame_top, width=10, font=("Arial", 12))
        self.end_port.insert(0, "1000")
        self.end_port.grid(row=0, column=5, padx=5)

        self.scan_button = Button(
            frame_top,
            text="Iniciar Varredura",
            command=self.iniciar_thread,
            bg="#00b894",
            fg="white",
            font=("Arial", 12, "bold")
        )

        self.scan_button.grid(row=0, column=6, padx=10)

        self.save_button = Button(
            frame_top,
            text="Salvar Resultado",
            command=self.salvar_resultados,
            bg="#0984e3",
            fg="white",
            font=("Arial", 12, "bold")
        )

        self.save_button.grid(row=0, column=7, padx=10)

        # ======================================
        # TABELA
        # ======================================

        self.tree = ttk.Treeview(
            root,
            columns=("porta", "status", "servico", "banner"),
            show="headings"
        )

        self.tree.heading("porta", text="Porta")
        self.tree.heading("status", text="Status")
        self.tree.heading("servico", text="Serviço")
        self.tree.heading("banner", text="Banner")

        self.tree.column("porta", width=80)
        self.tree.column("status", width=120)
        self.tree.column("servico", width=150)
        self.tree.column("banner", width=550)

        self.tree.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # ======================================
        # STATUS
        # ======================================

        self.status_label = Label(
            root,
            text="Aguardando varredura...",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 11)
        )

        self.status_label.pack(pady=5)

    # ======================================
    # THREAD
    # ======================================

    def iniciar_thread(self):

        thread = threading.Thread(
            target=self.varrer_portas
        )

        thread.daemon = True
        thread.start()

    # ======================================
    # SCAN PORTA
    # ======================================

    def scan_porta(self, ip, porta):

        try:

            resultado = scanner_nmap.scan(
                hosts=ip,
                ports=str(porta),
                arguments='-Pn -sT -T4'
            )

            if ip not in resultado['scan']:

                self.tree.insert(
                    '',
                    END,
                    values=(porta, 'SEM RESPOSTA', '-', '-')
                )

                return False

            tcp_data = resultado['scan'][ip].get('tcp', {})

            if porta not in tcp_data:

                self.tree.insert(
                    '',
                    END,
                    values=(porta, 'FECHADA', '-', '-')
                )

                return False

            estado = tcp_data[porta]['state']

            if estado == 'open':

                servico = tcp_data[porta].get(
                    'name',
                    'Desconhecido'
                )

                banner = tcp_data[porta].get(
                    'product',
                    'Sem banner'
                )

                self.resultados.append([
                    porta,
                    'ABERTA',
                    servico,
                    banner
                ])

                self.tree.insert(
                    '',
                    END,
                    values=(
                        porta,
                        'ABERTA',
                        servico,
                        banner
                    )
                )

                return True

            else:

                self.tree.insert(
                    '',
                    END,
                    values=(
                        porta,
                        estado.upper(),
                        '-',
                        '-'
                    )
                )

                return False

        except Exception as erro:

            self.tree.insert(
                '',
                END,
                values=(
                    porta,
                    'ERRO',
                    '-',
                    str(erro)
                )
            )

            return False

    # ======================================
    # VARREDURA
    # ======================================

    def varrer_portas(self):

        self.tree.delete(*self.tree.get_children())
        self.resultados.clear()

        ip = self.ip_entry.get()

        try:

            inicio = int(self.start_port.get())
            fim = int(self.end_port.get())

        except:

            messagebox.showerror(
                "Erro",
                "Portas inválidas"
            )

            return

        abertas = 0
        fechadas = 0

        self.status_label.config(
            text="Varredura em andamento..."
        )

        tempo_inicio = time.time()

        with ThreadPoolExecutor(
            max_workers=MAX_THREADS
        ) as executor:

            futures = []

            for porta in range(inicio, fim + 1):

                futures.append(
                    executor.submit(
                        self.scan_porta,
                        ip,
                        porta
                    )
                )

            for future in futures:

                if future.result():
                    abertas += 1
                else:
                    fechadas += 1

        tempo_final = time.time()

        tempo_total = round(
            tempo_final - tempo_inicio,
            2
        )

        resumo = (
            f"Scan finalizado | "
            f"Abertas: {abertas} | "
            f"Fechadas: {fechadas} | "
            f"Tempo: {tempo_total}s"
        )

        self.status_label.config(text=resumo)

        messagebox.showinfo(
            "Concluído",
            resumo
        )

    # ======================================
    # SALVAR
    # ======================================

    def salvar_resultados(self):

        if not self.resultados:

            messagebox.showwarning(
                "Aviso",
                "Nenhum resultado para salvar"
            )

            return

        caminho = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV", "*.csv"),
                ("TXT", "*.txt")
            ]
        )

        if not caminho:
            return

        try:

            if caminho.endswith(".csv"):

                with open(
                    caminho,
                    "w",
                    newline="",
                    encoding="utf-8"
                ) as arquivo:

                    writer = csv.writer(arquivo)

                    writer.writerow([
                        "Porta",
                        "Status",
                        "Serviço",
                        "Banner"
                    ])

                    writer.writerows(self.resultados)

            else:

                with open(
                    caminho,
                    "w",
                    encoding="utf-8"
                ) as arquivo:

                    for linha in self.resultados:

                        arquivo.write(
                            f"Porta: {linha[0]} | "
                            f"Status: {linha[1]} | "
                            f"Serviço: {linha[2]} | "
                            f"Banner: {linha[3]}\n"
                        )

            messagebox.showinfo(
                "Sucesso",
                "Resultados salvos com sucesso"
            )

        except Exception as erro:

            messagebox.showerror(
                "Erro",
                str(erro)
            )

# ======================================
# EXECUÇÃO
# ======================================

if __name__ == "__main__":

    root = Tk()

    app = ScannerGUI(root)

    root.mainloop()