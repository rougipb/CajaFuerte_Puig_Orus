using System;
using System.IO;
using System.Security.Cryptography;

/*
===============================================================================
PROYECTO: CajaFuerte
COMPATIBILIDAD: .NET Framework 4.7.2
ESTÁNDAR APLICADO: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
===============================================================================
DOCUMENTACIÓN DEL FORMATO BINARIO (.caja):
1. Sal (Salt): 16 bytes (Generada aleatoriamente con RNGCryptoServiceProvider)
2. IV: 16 bytes (Generado aleatoriamente para AES-256-CBC)
3. HMAC-SHA256 Tag: 32 bytes (Firma de autenticación e integridad)
4. Ciphertext: Longitud variable (Datos cifrados)
===============================================================================
*/

namespace CajaFuerte
{
    internal class Program
    {
        private const int SALT_SIZE = 16;       // 128 bits
        private const int IV_SIZE = 16;         // 128 bits (Bloque AES)
        private const int HMAC_SIZE = 32;       // 256 bits (HMAC-SHA256)
        private const int KEY_SIZE = 32;        // 256 bits (AES-256)
        private const int ITERATIONS = 600000;  // 600.000 iteraciones (Estándar OWASP)

        static int Main(string[] args)
        {
            if (args.Length != 4)
            {
                MostrarUso();
                return 1;
            }

            string modo = args[0].ToLower();
            string rutaEntrada = args[1];
            string rutaSalida = args[2];
            string contrasena = args[3];

            try
            {
                if (modo == "cifrar")
                {
                    CifrarFichero(rutaEntrada, rutaSalida, contrasena);
                    Console.WriteLine(" Fichero cifrado con éxito y verificado criptográficamente.");
                    return 0;
                }
                else if (modo == "descifrar")
                {
                    DescifrarFichero(rutaEntrada, rutaSalida, contrasena);
                    Console.WriteLine(" Fichero descifrado con éxito. La integridad ha sido validada.");
                    return 0;
                }
                else
                {
                    Console.WriteLine(" Error: Modo no reconocido. Usa 'cifrar' o 'descifrar'.");
                    MostrarUso();
                    return 1;
                }
            }
            catch (CryptographicException)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(" ERROR DE SEGURIDAD / INTEGRIDAD: El fichero ha sido manipulado o la contraseña es incorrecta.");
                Console.ResetColor();
                return 2;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($" ERROR: {ex.Message}");
                Console.ResetColor();
                return 3;
            }
        }

        private static void CifrarFichero(string rutaEntrada, string rutaSalida, string contrasena)
        {
            if (!File.Exists(rutaEntrada))
                throw new FileNotFoundException($"El fichero de entrada '{rutaEntrada}' no existe.");

            byte[] datosOriginales = File.ReadAllBytes(rutaEntrada);

            // 1. Generar Sal e IV de forma aleatoria y segura (CSRNG)
            byte[] salt = GenerarBytesAleatorios(SALT_SIZE);
            byte[] iv = GenerarBytesAleatorios(IV_SIZE);

            // 2. Derivar Clave de Cifrado (256 bits) y Clave HMAC (256 bits) usando PBKDF2
            byte[] claveCifrado = DerivarClave(contrasena, salt, "EncryptionKey", KEY_SIZE);
            byte[] claveHmac = DerivarClave(contrasena, salt, "HMACKey", KEY_SIZE);

            // 3. Cifrar con AES-256 en modo CBC con relleno PKCS7
            byte[] ciphertext;
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = claveCifrado;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(datosOriginales, 0, datosOriginales.Length);
                        cs.FlushFinalBlock();
                    }
                    ciphertext = ms.ToArray();
                }
            }

            // 4. Autenticar: Calcular HMAC-SHA256 sobre (IV + Ciphertext) -> Encrypt-then-MAC
            byte[] hmacTag;
            using (HMACSHA256 hmac = new HMACSHA256(claveHmac))
            {
                byte[] payloadAAutenticar = ConcatArrays(iv, ciphertext);
                hmacTag = hmac.ComputeHash(payloadAAutenticar);
            }

            // 5. Guardar la estructura binaria en el fichero .caja
            using (FileStream fs = new FileStream(rutaSalida, FileMode.Create, FileAccess.Write))
            using (BinaryWriter writer = new BinaryWriter(fs))
            {
                writer.Write(salt);       // 16 bytes
                writer.Write(iv);         // 16 bytes
                writer.Write(hmacTag);    // 32 bytes
                writer.Write(ciphertext); // Resto del archivo
            }

            // Limpieza de claves en memoria
            Array.Clear(claveCifrado, 0, claveCifrado.Length);
            Array.Clear(claveHmac, 0, claveHmac.Length);
        }

        private static void DescifrarFichero(string rutaEntrada, string rutaSalida, string contrasena)
        {
            if (!File.Exists(rutaEntrada))
                throw new FileNotFoundException($"El fichero cifrado '{rutaEntrada}' no existe.");

            byte[] bytesFichero = File.ReadAllBytes(rutaEntrada);
            int cabeceraMinima = SALT_SIZE + IV_SIZE + HMAC_SIZE;

            if (bytesFichero.Length < cabeceraMinima)
                throw new CryptographicException("El fichero no tiene un formato válido o está corrompido.");

            // 1. Extraer los componentes según la estructura definida
            byte[] salt = new byte[SALT_SIZE];
            byte[] iv = new byte[IV_SIZE];
            byte[] hmacGuardado = new byte[HMAC_SIZE];
            int ciphertextLength = bytesFichero.Length - cabeceraMinima;
            byte[] ciphertext = new byte[ciphertextLength];

            Buffer.BlockCopy(bytesFichero, 0, salt, 0, SALT_SIZE);
            Buffer.BlockCopy(bytesFichero, SALT_SIZE, iv, 0, IV_SIZE);
            Buffer.BlockCopy(bytesFichero, SALT_SIZE + IV_SIZE, hmacGuardado, 0, HMAC_SIZE);
            Buffer.BlockCopy(bytesFichero, cabeceraMinima, ciphertext, 0, ciphertextLength);

            // 2. Derivar las claves idénticas con la Sal extraída
            byte[] claveCifrado = DerivarClave(contrasena, salt, "EncryptionKey", KEY_SIZE);
            byte[] claveHmac = DerivarClave(contrasena, salt, "HMACKey", KEY_SIZE);

            // 3. Validar INTEGRIDAD PRIMERO (Verificar HMAC antes de intentar descifrar)
            using (HMACSHA256 hmac = new HMACSHA256(claveHmac))
            {
                byte[] payloadAAutenticar = ConcatArrays(iv, ciphertext);
                byte[] hmacCalculado = hmac.ComputeHash(payloadAAutenticar);

                if (!CompararTiempoConstante(hmacGuardado, hmacCalculado))
                {
                    // Lanza excepción si el archivo ha sido manipulado o la clave es mala
                    throw new CryptographicException("La firma de integridad (HMAC) no coincide.");
                }
            }

            // 4. Descifrar si la autenticación fue correcta
            byte[] datosDescifrados;
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = claveCifrado;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(ciphertext, 0, ciphertext.Length);
                        cs.FlushFinalBlock();
                    }
                    datosDescifrados = ms.ToArray();
                }
            }

            File.WriteAllBytes(rutaSalida, datosDescifrados);

            // Limpieza de memoria
            Array.Clear(claveCifrado, 0, claveCifrado.Length);
            Array.Clear(claveHmac, 0, claveHmac.Length);
        }

        private static byte[] DerivarClave(string contrasena, byte[] salt, string proposito, int bytesRequeridos)
        {
            // Derivación segura mediante PBKDF2 (HMAC-SHA256) con 600.000 iteraciones
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(contrasena + proposito, salt, ITERATIONS, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(bytesRequeridos);
            }
        }

        private static byte[] GenerarBytesAleatorios(int cantidad)
        {
            byte[] buffer = new byte[cantidad];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(buffer);
            }
            return buffer;
        }

        private static byte[] ConcatArrays(byte[] a, byte[] b)
        {
            byte[] resultado = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, resultado, 0, a.Length);
            Buffer.BlockCopy(b, 0, resultado, a.Length, b.Length);
            return resultado;
        }

        private static bool CompararTiempoConstante(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        private static void MostrarUso()
        {
            Console.WriteLine("\nSintaxis de uso:");
            Console.WriteLine("  CajaFuerte cifrar   <fichero_entrada> <fichero_salida.caja> <contraseña>");
            Console.WriteLine("  CajaFuerte descifrar <fichero_salida.caja> <fichero_recuperado> <contraseña>\n");
        }
    }
}