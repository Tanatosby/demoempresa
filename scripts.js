import { initializeApp } from "https://www.gstatic.com/firebasejs/9.20.0/firebase-app.js"
import { getDatabase, ref, push, onValue, remove, update } from "https://www.gstatic.com/firebasejs/9.20.0/firebase-database.js"

const firebaseConfig = {
  databaseURL: "https://test21-e8c4214-default-rt2231db.fi312aseio.com/"
}

const app = initializeApp(firebaseConfig)
const database = getDatabase(app)
const users = ref(database, "Users")

// Page elements
const Id = document.getElementById("id")
const nameInput = document.getElementById("name")
const usernameInput = document.getElementById("username")
const passwordInput = document.getElementById("password")
const submits = document.getElementById("submit")
const role = document.getElementById("role")


// 🔐 Función para encriptar password con PBKDF2 + salt aleatorio
async function hashPassword(password) {
  const encoder = new TextEncoder()

  // Generar salt aleatorio (16 bytes)
  const salt = crypto.getRandomValues(new Uint8Array(16))

  // Importar la contraseña como clave base
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  )

  // Derivar el hash con PBKDF2
  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,   // 100k iteraciones = más seguro
      hash: "SHA-256"
    },
    keyMaterial,
    256 // 32 bytes de output
  )

  // Convertir a hex string para guardar
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  const saltArray = Array.from(salt)

  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("")
  const saltHex = saltArray.map(b => b.toString(16).padStart(2, "0")).join("")

  // Guardamos salt:hash juntos para poder verificar luego
  return `${saltHex}:${hashHex}`
}


// 🚀 Submit con password encriptado
submits.addEventListener("click", async function () {
  const rawPassword = passwordInput.value

  // Validación básica
  if (!Id.value || !nameInput.value || !usernameInput.value || !rawPassword) {
    alert("Por favor complete todos los campos.")
    return
  }

  try {
    // Encriptar antes de enviar
    const encryptedPassword = await hashPassword(rawPassword)

    const userInput = {
      ID: Id.value,
      Name: nameInput.value,
      Username: usernameInput.value,
      Password: encryptedPassword,   // ✅ Ya encriptado
      Role: role.value  
    }

    await push(users, userInput)
    console.log("✅ Usuario guardado con password encriptado")

    // Limpiar campos
    Id.value = ""
    nameInput.value = ""
    usernameInput.value = ""
    passwordInput.value = ""

  } catch (error) {
    console.error("❌ Error al guardar usuario:", error)
  }
})
