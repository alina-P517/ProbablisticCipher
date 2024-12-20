from tkinter import *
from tkinter.scrolledtext import ScrolledText
import random

class InterfaceApp:

    def __init__(self, root):
        self.root = root
        self.root['bg'] = '#cddafa'
        self.root.title('Вероятностный шифр')
        self.root.geometry('1100x600')

        frame = Frame(root, bg='white')
        frame.place(relx=0.05, rely=0.08, width=1000, height=500)

        labelInpt = Label(frame, text='Введите текст:', bg='#cddafa', font=10, anchor="nw")
        labelInpt.grid(row=0, column=0, padx=80, pady=5, sticky='w')

        self.textInpt = ScrolledText(frame, width=100, height=8, relief="solid")
        self.textInpt.grid(row=1, column=0, padx=80, pady=5, sticky='w')

        labelKey = Label(frame, text='Ключ:', bg='#cddafa', font=10, anchor="nw")
        labelKey.grid(row=4, column=0, padx=80, pady=5, sticky='w')

        self.key = Entry(frame, width=133, borderwidth=1, relief="solid")
        self.key.grid(row=6, column=0, padx=80, pady=5, sticky="w")

        labelOutpt = Label(frame, text='Результат:', bg='#cddafa', font=10, anchor="nw")
        labelOutpt.grid(row=7, column=0, padx=80, pady=5, sticky='w')

        self.textOutpt = ScrolledText(frame, width=100, height=8, relief="solid")
        self.textOutpt.grid(row=8, column=0, padx=80, pady=5, sticky='w')
        self.textOutpt.config(state=DISABLED)

        btnEncrypt = Button(frame, text='Зашифровать', bg='#cddafa', command=self.encrypt)
        btnEncrypt.grid(row=10, column=0, sticky="w", padx=80, pady=10)

        btnDecrypt = Button(frame, text='Расшифровать', bg='#cddafa', command=self.decrypt)
        btnDecrypt.grid(row=10, column=0, sticky="w", padx=180, pady=10)

    def generateKey(self, length):
        """Генерация случайного ключа заданной длины."""
        key = bytearray(length)
        for i in range(length):
            key[i] = random.getrandbits(8)
        return bytes(key)

    def encrypt(self):
        plaintext = self.textInpt.get("1.0", END).strip().encode()
        if not plaintext:
            return

        userKey = self.key.get().strip()
        if userKey:
            try:
                key = bytes.fromhex(userKey)
                if len(key) != len(plaintext):
                    raise ValueError("Длина ключа должна совпадать с длиной текста.")
            except ValueError:
                self.textOutpt.config(state=NORMAL)
                self.textOutpt.delete("1.0", END)
                self.textOutpt.insert(END, "Некорректный ключ!")
                self.textOutpt.config(state=DISABLED)
                return
        else:
            key = self.generateKey(len(plaintext))


        randomVector = self.generateKey(len(plaintext))
        ciphertext = bytes([p ^ k ^ r for p, k, r in zip(plaintext, key, randomVector)])

        # Сохранение случайного вектора и шифротекста
        output = randomVector + ciphertext

        self.textOutpt.config(state=NORMAL)
        self.textOutpt.delete("1.0", END)
        self.textOutpt.insert(END, output.hex())
        self.textOutpt.config(state=DISABLED)

        self.key.delete(0, END)
        self.key.insert(0, key.hex())

    def decrypt(self):
        combinedHex = self.textOutpt.get("1.0", END).strip()
        keyHex = self.key.get().strip()

        if not combinedHex or not keyHex:
            return

        try:
            combined = bytes.fromhex(combinedHex)
            key = bytes.fromhex(keyHex)
        except ValueError:
            self.textOutpt.config(state=NORMAL)
            self.textOutpt.delete("1.0", END)
            self.textOutpt.insert(END, "Некорректный формат ключа или текста!")
            self.textOutpt.config(state=DISABLED)
            return

        if len(combined) < len(key):
            self.textOutpt.config(state=NORMAL)
            self.textOutpt.delete("1.0", END)
            self.textOutpt.insert(END, "Длина ключа должна быть меньше длины шифротекста!")
            self.textOutpt.config(state=DISABLED)
            return

        randomVector = combined[:len(combined) - len(key)]
        ciphertext = combined[len(randomVector):]

        plaintext = bytes([c ^ k ^ r for c, k, r in zip(ciphertext, key, randomVector)])

        self.textOutpt.config(state=NORMAL)
        self.textOutpt.delete("1.0", END)
        self.textOutpt.insert(END, plaintext.decode(errors='ignore'))
        self.textOutpt.config(state=DISABLED)

if __name__ == '__main__':
    root = Tk()
    app = InterfaceApp(root)
    root.mainloop()
