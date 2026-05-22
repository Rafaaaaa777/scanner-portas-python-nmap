import socket
import threading
import time
import csv

from concurrent.futures import ThreadPoolExecutor

from tkinter import *
from tkinter import ttk, filedialog, messagebox

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# ======================================
# CONFIGURAÇÕES
# ======================================

TIMEOUT = 2
MAX_THREADS = 100

# ======================================
# FUNÇÕES AUXILIARES
# ======================================

def obter_servico(porta):

    try:
        return socket.getservbyport(porta)

    except:
        return "Desconhecido"


def banner_grabbing(sock):

    try:

        sock.settimeout(1)

        banner = sock.recv(1024).decode(
            errors="ignore"
        ).strip()

        if banner:
            return banner

        return "Sem banner"

    except:

        return "Sem banner"

# ======================================
# CLASSE PRINCIPAL
# ======================================

class ScannerGUI:

    def __init__(self, root):

        self.root = root

        self.root.title("Scanner TCP com Socket")

        self.root.geometry("1100x700")

        self.root.configure(bg="#1e1e1e")

        self.resultados = []

        # ======================================
        # TÍTULO
        # ======================================

        titulo = Label(
            root,
            text="Scanner TCP - Python Socket",
            font=("Arial", 22, "bold"),
            bg="#1e1e1e",
            fg="white"
        )

        titulo.pack(pady=15)

        # ======================================
        # TOPO
        # ======================================

        frame_top = Frame(
            root,
            bg="#1e1e1e"
        )

        frame_top.pack(pady=10)

        Label(
            frame_top,
            text="IP:",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 12)
        ).grid(row=0, column=0, padx=5)

        self.ip_entry = Entry(
            frame_top,
            width=18,
            font=("Arial", 12)
        )

        self.ip_entry.insert(0, "127.0.0.1")

        self.ip_entry.grid(
            row=0,
            column=1,
            padx=5
        )

        Label(
            frame_top,
            text="Porta Inicial:",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 12)
        ).grid(row=0, column=2, padx=5)

        self.start_port = Entry(
            frame_top,
            width=10,
            font=("Arial", 12)
        )

        self.start_port.insert(0, "1")

        self.start_port.grid(
            row=0,
            column=3,
            padx=5
        )

        Label(
            frame_top,
            text="Porta Final:",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 12)
        ).grid(row=0, column=4, padx=5)

        self.end_port = Entry(
            frame_top,
            width=10,
            font=("Arial", 12)
        )

        self.end_port.insert(0, "1000")

        self.end_port.grid(
            row=0,
            column=5,
            padx=5
        )

        # ======================================
        # BOTÃO SCAN
        # ======================================

        self.scan_button = Button(
            frame_top,
            text="Iniciar Varredura",
            command=self.iniciar_thread,
            bg="#00b894",
            fg="white",
            font=("Arial", 12, "bold")
        )

        self.scan_button.grid(
            row=0,
            column=6,
            padx=10
        )

        # ======================================
        # BOTÃO SALVAR
        # ======================================

        self.save_button = Button(
            frame_top,
            text="Salvar TXT/CSV",
            command=self.salvar_resultados,
            bg="#0984e3",
            fg="white",
            font=("Arial", 12, "bold")
        )

        self.save_button.grid(
            row=0,
            column=7,
            padx=10
        )

        # ======================================
        # BOTÃO PDF
        # ======================================

        self.pdf_button = Button(
            frame_top,
            text="Gerar PDF",
            command=self.gerar_pdf,
            bg="#6c5ce7",
            fg="white",
            font=("Arial", 12, "bold")
        )

        self.pdf_button.grid(
            row=0,
            column=8,
            padx=10
        )

        # ======================================
        # TABELA
        # ======================================

        self.tree = ttk.Treeview(
            root,
            columns=(
                "porta",
                "status",
                "servico",
                "banner"
            ),
            show="headings"
        )

        self.tree.heading(
            "porta",
            text="Porta"
        )

        self.tree.heading(
            "status",
            text="Status"
        )

        self.tree.heading(
            "servico",
            text="Serviço"
        )

        self.tree.heading(
            "banner",
            text="Banner"
        )

        self.tree.column(
            "porta",
            width=80
        )

        self.tree.column(
            "status",
            width=120
        )

        self.tree.column(
            "servico",
            width=150
        )

        self.tree.column(
            "banner",
            width=650
        )

        self.tree.pack(
            fill=BOTH,
            expand=True,
            padx=10,
            pady=10
        )

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

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(TIMEOUT)

        try:

            resultado = sock.connect_ex(
                (ip, porta)
            )

            # 0 = conexão aceita
            # SYN -> SYN/ACK -> ACK

            if resultado == 0:

                servico = obter_servico(porta)

                banner = banner_grabbing(sock)

                self.resultados.append([
                    porta,
                    "ABERTA",
                    servico,
                    banner
                ])

                self.tree.insert(
                    '',
                    END,
                    values=(
                        porta,
                        "ABERTA",
                        servico,
                        banner
                    )
                )

                return True

            else:

                self.resultados.append([
                    porta,
                    "FECHADA",
                    "-",
                    "-"
                ])

                self.tree.insert(
                    '',
                    END,
                    values=(
                        porta,
                        "FECHADA",
                        "-",
                        "-"
                    )
                )

                return False

        except Exception as erro:

            self.tree.insert(
                '',
                END,
                values=(
                    porta,
                    "ERRO",
                    "-",
                    str(erro)
                )
            )

            return False

        finally:

            sock.close()

    # ======================================
    # VARREDURA
    # ======================================

    def varrer_portas(self):

        self.tree.delete(
            *self.tree.get_children()
        )

        self.resultados.clear()

        ip = self.ip_entry.get()

        try:

            inicio = int(
                self.start_port.get()
            )

            fim = int(
                self.end_port.get()
            )

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

            for porta in range(
                inicio,
                fim + 1
            ):

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

        self.status_label.config(
            text=resumo
        )

        messagebox.showinfo(
            "Concluído",
            resumo
        )

    # ======================================
    # SALVAR TXT/CSV
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

                    writer = csv.writer(
                        arquivo
                    )

                    writer.writerow([
                        "Porta",
                        "Status",
                        "Serviço",
                        "Banner"
                    ])

                    writer.writerows(
                        self.resultados
                    )

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
                "Arquivo salvo com sucesso"
            )

        except Exception as erro:

            messagebox.showerror(
                "Erro",
                str(erro)
            )

    # ======================================
    # GERAR PDF
    # ======================================

    def gerar_pdf(self):

        abertas = []

        for item in self.resultados:

            if item[1] == "ABERTA":

                abertas.append(item)

        if not abertas:

            messagebox.showwarning(
                "Aviso",
                "Nenhuma porta aberta encontrada"
            )

            return

        caminho = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf")]
        )

        if not caminho:
            return

        try:

            doc = SimpleDocTemplate(
                caminho
            )

            elementos = []

            estilos = getSampleStyleSheet()

            titulo = Paragraph(
                "Relatório de Portas Abertas",
                estilos['Title']
            )

            elementos.append(titulo)

            elementos.append(
                Spacer(1, 20)
            )

            subtitulo = Paragraph(
                f"IP Escaneado: {self.ip_entry.get()}",
                estilos['Heading2']
            )

            elementos.append(subtitulo)

            elementos.append(
                Spacer(1, 15)
            )

            dados = [
                [
                    "Porta",
                    "Status",
                    "Serviço",
                    "Banner"
                ]
            ]

            for linha in abertas:

                dados.append(linha)

            tabela = Table(dados)

            tabela.setStyle(

                TableStyle([

                    (
                        'BACKGROUND',
                        (0, 0),
                        (-1, 0),
                        colors.darkblue
                    ),

                    (
                        'TEXTCOLOR',
                        (0, 0),
                        (-1, 0),
                        colors.white
                    ),

                    (
                        'GRID',
                        (0, 0),
                        (-1, -1),
                        1,
                        colors.black
                    ),

                    (
                        'FONTNAME',
                        (0, 0),
                        (-1, 0),
                        'Helvetica-Bold'
                    ),

                    (
                        'BACKGROUND',
                        (0, 1),
                        (-1, -1),
                        colors.beige
                    )

                ])

            )

            elementos.append(tabela)

            elementos.append(
                Spacer(1, 20)
            )

            rodape = Paragraph(
                "Relatório gerado automaticamente pelo Scanner TCP",
                estilos['Normal']
            )

            elementos.append(rodape)

            doc.build(elementos)

            messagebox.showinfo(
                "Sucesso",
                "PDF gerado com sucesso"
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