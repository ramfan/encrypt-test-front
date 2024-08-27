import "./App.css";
import { FormEventHandler, useEffect, useState } from "react";
import axios from "axios";
import queryString from "query-string";

const client = axios.create({
  baseURL: "http://localhost:3000",
  paramsSerializer: (data: object): string => {
    return queryString.stringify(data, { arrayFormat: "none" });
  },
  headers: {
    Accept: "application/json",
    "Content-Type": "application/json",
  },
});

function App() {
  const [file, setFile] = useState<File | null>();
  const [message, setMessage] = useState<string | undefined>();
  const [decryptionResult, setDecriptionResult] = useState<
    string | undefined
  >();
  const [encryptedMessage, setEncryptedMessage] = useState<
    string | undefined
  >();
  const [serverPublicKey, setServerPublicKey] = useState("");
  const { encryptData } = useCrypto(serverPublicKey);

  useEffect(() => {
    client.get<string>("/key").then(({ data }) => {
      setServerPublicKey(data);
    });
  }, []);

  const handleSubmit: FormEventHandler = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const formData = new FormData();
    if (file) {
      const reader = new FileReader();
      reader.onload = async (e) => {
        const data = e.target?.result;
        if (data) {
          try {
            const { encryptedData, iv, encryptedKey } = await encryptData(data);
            const encryptedArr = new Uint8Array(
              encryptedData,
              0,
              encryptedData.byteLength,
            );
            const blob = new Blob([encryptedArr.buffer]);
            const encryptedFile = new File([blob], file.name);
            formData.append("file", encryptedFile);
            formData.append("iv", btob(iv));
            formData.append("key", btob(encryptedKey));
            await client.post("/upload", formData, {
              paramsSerializer: undefined,
              headers: { "Content-Type": "multipart/form-data" },
            });
          } catch (e) {
            console.error(e);
          }
        }
      };
      reader.readAsArrayBuffer(file);
    }

    if (message) {
      const { encryptedData, encryptedKey, iv } = await encryptData(message);
      const decodedData = btob(encryptedData);
      const decodedKey = btob(encryptedKey);
      const decodedIv = btob(iv);
      setEncryptedMessage(new TextDecoder().decode(encryptedData));

      setDecriptionResult(
        (
          await client.post("/decryptText", {
            message: decodedData,
            key: decodedKey,
            iv: decodedIv,
          })
        ).data,
      );
    }
  };

  return (
    <form onSubmit={handleSubmit} className="upload-form">
      {message && (
        <div>
          <span>message: </span>
          <span>{message}</span>
        </div>
      )}
      {message && encryptedMessage && (
        <div>
          <span>encryptedMessage: </span>
          <span>{encryptedMessage}</span>
        </div>
      )}

      {message && decryptionResult && (
        <div>
          <span>decryptionResult: </span>
          <span>{decodeURIComponent(decryptionResult)}</span>
        </div>
      )}
      <input
        onChange={(el) => {
          setMessage(el.target.value);
        }}
      />
      <input
        type="file"
        onChange={(el) => {
          setFile(el.target.files?.item(0));
        }}
      />
      <button type="submit">Send</button>
    </form>
  );
}

export default App;

/**
 * Базовый алгоритм шифрования файлов с использованием RSA ключа
 * У RSA есть ограничение по количеству информации, которую можно зашифровать
 * В случае с 4096 битным ключом и хэш-функцией SHA-1, можно зашифровать 470 байт информации.
 *
 * Для шифрования файлов можно использовать метод шифрования AES-CBC, ключ шифрования сгенерировать и зашифровать ключом RSA
 * и отправлять его на сервере.
 * Шаги:
 * 1) Получить публичный путь
 * 2) Сгенерировать ключ шифрования для AES-CBC
 * 3) Зашифровать данные
 * 4) Зашифровать ключ шифрования публичным ключом
 * 5) Вернуть зашифрованные данные и зашифрованный ключ
 * 6) Вернуть параметр iv
 */
const useCrypto = (publicKeyFromServer: string) => {
  const [publicKey, setPublicKey] = useState(publicKeyFromServer);

  useEffect(() => {
    setPublicKey(publicKeyFromServer);
  }, [publicKeyFromServer]);

  const encryptData = async (data: string | ArrayBuffer) => {
    try {
      const key = await generateAESKey();
      const exportedKey = await exportKey(key);
      const encryptedKey = await encryptKey(exportedKey);
      const iv = window.crypto.getRandomValues(new Uint8Array(16));
      const encryptedData = await window.crypto.subtle.encrypt(
        {
          name: "AES-CBC",
          iv,
        },
        key,
        prepareData(data),
      );

      return { encryptedKey, encryptedData, iv };
    } catch (err) {
      console.log("Error encrypting data: ", err);
      throw err;
    }
  };

  const exportKey = async (key: CryptoKey) => {
    try {
      return await window.crypto.subtle.exportKey("raw", key);
    } catch (err) {
      console.log("Error key export: ", err);
      throw err;
    }
  };

  const encryptKey = async (encryptionKey: ArrayBuffer) => {
    try {
      const importedKey = await importFromRSAKey();
      return await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedKey,
        encryptionKey,
      );
    } catch (err) {
      console.log("Error encryption encrypt key: ", err);
      throw err;
    }
  };

  const prepareData = (data: string | ArrayBuffer): ArrayBuffer => {
    if (typeof data === "string") {
      return stob(data);
    }

    return data;
  };

  const generateAESKey = async () => {
    try {
      return await window.crypto.subtle.generateKey(
        {
          name: "AES-CBC",
          length: 256,
        },
        true,
        ["encrypt", "decrypt"],
      );
    } catch (err) {
      console.error("Generate key error: " + err);
      throw err;
    }
  };

  const importFromRSAKey = async () => {
    try {
      return await window.crypto.subtle.importKey(
        "spki",
        stob(window.atob(publicKey)),
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        false,
        ["encrypt"],
      );
    } catch (e) {
      console.error("Import key error: " + e);
      throw e;
    }
  };

  return { encryptData };
};

const btob = (data: ArrayBuffer) => {
  let res = "";
  const bList = new Uint8Array(data);
  for (let i = 0; i < bList.length; i++) {
    res += String.fromCharCode(bList[i]);
  }
  return btoa(res);
};

const stob = (s: string) => {
  const buf = new ArrayBuffer(s.length);
  const bList = new Uint8Array(buf);
  for (let i = 0; i < s.length; i++) {
    bList[i] = s.charCodeAt(i);
  }
  return bList.buffer;
};
