import { initializeApp }                          from "https://www.gstatic.com/firebasejs/9.20.0/firebase-app.js"
import { getDatabase, ref, push, onValue,
         remove, update, get, set, child }        from "https://www.gstatic.com/firebasejs/9.20.0/firebase-database.js"

// ─── FIREBASE CONFIG ────────────────────────────────────────────
const firebaseConfig = {
  databaseURL: "https://test01-e8ca4-default-rtdb.firebaseio.com"
}

const app      = initializeApp(firebaseConfig)
const database = getDatabase(app)

// ─── DATABASE REFS ──────────────────────────────────────────────
const usersRef  = ref(database, "Users")
const tareasRef = ref(database, "Tareas")

// ═══════════════════════════════════════════════════════════════
//  CRYPTO UTILITIES
// ═══════════════════════════════════════════════════════════════

/**
 * Converts an ArrayBuffer to a hex string.
 */
function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}

/**
 * Converts a hex string back to a Uint8Array.
 */
function hexToUint8Array(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

/**
 * Hashes a password using PBKDF2 + SHA-256 with a random salt.
 * Returns a string in the format  "saltHex:hashHex"
 */
export async function hashPassword(password) {
  const encoder    = new TextEncoder()
  const salt       = crypto.getRandomValues(new Uint8Array(16))

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  )

  const hashBuffer = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  )

  const saltHex = bufferToHex(salt.buffer)
  const hashHex = bufferToHex(hashBuffer)
  return `${saltHex}:${hashHex}`
}

/**
 * Verifies a plain-text password against a stored "saltHex:hashHex" string.
 * Returns true if they match, false otherwise.
 */
export async function verifyPassword(plainPassword, storedValue) {
  try {
    const [saltHex, hashHex] = storedValue.split(":")
    if (!saltHex || !hashHex) return false

    const encoder     = new TextEncoder()
    const salt        = hexToUint8Array(saltHex)
    const storedBytes = hexToUint8Array(hashHex)

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(plainPassword),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    )

    const hashBuffer = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
      keyMaterial,
      256
    )

    const newBytes = new Uint8Array(hashBuffer)

    // Constant-time comparison to avoid timing attacks
    if (newBytes.length !== storedBytes.length) return false
    let diff = 0
    for (let i = 0; i < newBytes.length; i++) diff |= newBytes[i] ^ storedBytes[i]
    return diff === 0

  } catch {
    return false
  }
}

// ═══════════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════════

/**
 * Reads all users from Firebase and finds one whose username matches.
 * Verifies the password, then returns { uid, user, role } or throws.
 */
export async function loginUser(username, password) {
  const snapshot = await get(usersRef)

  if (!snapshot.exists()) throw new Error("No se encontraron usuarios en la base de datos.")

  const users = snapshot.val()
  let matchUid  = null
  let matchUser = null

  for (const [uid, data] of Object.entries(users)) {
    // Support both capitalizations: "Username" (Firebase) and "username"
    const storedUsername = data.Username ?? data.username ?? ""
    if (storedUsername === username) {
      matchUid  = uid
      matchUser = data
      break
    }
  }

  if (!matchUser) throw new Error("Usuario no encontrado.")

  // Support both capitalizations: "Password" (Firebase) and "password"
  const storedPassword = matchUser.Password ?? matchUser.password ?? ""
  const valid = await verifyPassword(password, storedPassword)
  if (!valid)  throw new Error("Contraseña incorrecta.")

  // Normalize fields to lowercase for internal use
  const normalizedUser = {
    id:       matchUser.ID       ?? matchUser.id       ?? "",
    name:     matchUser.Name     ?? matchUser.name     ?? "",
    username: matchUser.Username ?? matchUser.username ?? "",
    role:     matchUser.Role     ?? matchUser.role     ?? "",
    password: storedPassword
  }

  return { uid: matchUid, user: normalizedUser, role: normalizedUser.role }
}

/**
 * Saves the current session to sessionStorage.
 */
export function saveSession(uid, user, role) {
  sessionStorage.setItem("session", JSON.stringify({ uid, user, role }))
}

/**
 * Retrieves the current session from sessionStorage.
 * Returns null if there is no active session.
 */
export function getSession() {
  const raw = sessionStorage.getItem("session")
  return raw ? JSON.parse(raw) : null
}

/**
 * Clears the session and redirects to the login page.
 */
export function logout() {
  sessionStorage.removeItem("session")
  window.location.href = "index.html"
}

// ═══════════════════════════════════════════════════════════════
//  USERS MODULE  (admin only)
// ═══════════════════════════════════════════════════════════════

/**
 * Adds a new user to Firebase.
 * The password is hashed before storage.
 */
export async function addUser({ id, name, username, password, role }) {
  const hashed = await hashPassword(password)
  const newRef  = push(usersRef)
  await set(newRef, { id, name, username, password: hashed, role })
  return newRef.key
}

/**
 * Updates an existing user.
 * If a new password string is provided (non-empty), it is re-hashed.
 */
export async function updateUser(uid, { id, name, username, password, role }) {
  const updates = { id, name, username, role }
  if (password && password.trim() !== "") {
    updates.password = await hashPassword(password)
  }
  await update(ref(database, `Users/${uid}`), updates)
}

/**
 * Deletes a user by Firebase key (uid).
 */
export async function deleteUser(uid) {
  await remove(ref(database, `Users/${uid}`))
}

/**
 * Subscribes to the Users collection in real-time.
 * Calls callback(usersArray) whenever data changes.
 * Returns the unsubscribe function.
 */
export function subscribeUsers(callback) {
  return onValue(usersRef, snapshot => {
    const data  = snapshot.val() || {}
    const items = Object.entries(data).map(([uid, u]) => {
      const normalized = Object.fromEntries(
        Object.entries(u).map(([k, v]) => [k.toLowerCase(), v])
      )
      return { uid, ...normalized }
    })
    callback(items)
  })
}

// ═══════════════════════════════════════════════════════════════
//  TASKS MODULE  (user role)
// ═══════════════════════════════════════════════════════════════

/**
 * Adds a new task to Firebase under "Tareas".
 * Associates the task with the logged-in user's uid.
 */
export async function addTarea({ titulo, descripcion, fechaLimite, prioridad, ownerUid, ownerName }) {
  const newRef = push(tareasRef)
  await set(newRef, {
    titulo,
    descripcion,
    fechaLimite,
    prioridad,
    ownerUid,
    ownerName,
    createdAt: new Date().toISOString(),
    status: "pendiente"
  })
  return newRef.key
}

/**
 * Deletes a task by Firebase key.
 */
export async function deleteTarea(key) {
  await remove(ref(database, `Tareas/${key}`))
}

/**
 * Updates a task's status.
 */
export async function updateTareaStatus(key, status) {
  await update(ref(database, `Tareas/${key}`), { status })
}

/**
 * Subscribes to Tareas for a specific user (by ownerUid).
 * Calls callback(tareasArray) on each change.
 */
export function subscribeTareas(ownerUid, callback) {
  return onValue(tareasRef, snapshot => {
    const data  = snapshot.val() || {}
    const items = Object.entries(data)
      .map(([key, t]) => ({ key, ...t }))
      .filter(t => t.ownerUid === ownerUid)
    callback(items)
  })
}

// ═══════════════════════════════════════════════════════════════
//  LOGIN PAGE BOOTSTRAP
// ═══════════════════════════════════════════════════════════════

function initLoginPage() {
  // If already logged in, skip to console
  if (getSession()) {
    window.location.href = "console.html"
    return
  }

  const form    = document.getElementById("loginForm")
  const errBox  = document.getElementById("loginError")
  const btnText = document.getElementById("btnText")
  const spinner = document.getElementById("btnSpinner")

  if (!form) return   // Not on login page

  form.addEventListener("submit", async e => {
    e.preventDefault()
    const username = document.getElementById("username").value.trim()
    const password = document.getElementById("password").value

    // Show loading
    btnText.textContent = "Verificando…"
    spinner.style.display = "inline-block"
    errBox.classList.remove("visible")
    form.querySelector("button[type=submit]").disabled = true

    try {
      const { uid, user, role } = await loginUser(username, password)
      saveSession(uid, user, role)
      window.location.href = "console.html"
    } catch (err) {
      errBox.textContent = err.message
      errBox.classList.add("visible")
    } finally {
      btnText.textContent = "Iniciar sesión"
      spinner.style.display = "none"
      form.querySelector("button[type=submit]").disabled = false
    }
  })
}

// ═══════════════════════════════════════════════════════════════
//  CONSOLE PAGE BOOTSTRAP
// ═══════════════════════════════════════════════════════════════

// ── Toast helper ────────────────────────────────────────────────
function showToast(message, type = "info") {
  let container = document.getElementById("toast-container")
  if (!container) {
    container = document.createElement("div")
    container.id = "toast-container"
    document.body.appendChild(container)
  }

  const icons = { success: "✓", error: "✕", info: "ℹ" }
  const toast = document.createElement("div")
  toast.className = `toast ${type}`
  toast.innerHTML = `<span>${icons[type] || icons.info}</span><span>${message}</span>`
  container.appendChild(toast)

  setTimeout(() => {
    toast.classList.add("fadeout")
    toast.addEventListener("animationend", () => toast.remove())
  }, 3200)
}

// ── Module switcher ─────────────────────────────────────────────
function activateModule(id) {
  document.querySelectorAll(".module-panel").forEach(p => p.classList.remove("active"))
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"))
  const panel = document.getElementById(id)
  if (panel) panel.classList.add("active")
  document.querySelector(`[data-module="${id}"]`)?.classList.add("active")
  document.getElementById("topBarTitle").textContent =
    document.querySelector(`[data-module="${id}"]`)?.querySelector(".nav-label")?.textContent || ""
}

// ── Admin: render users table ───────────────────────────────────
function renderUsersTable(users,currentRole ) {
  const tbody = document.getElementById("usersTableBody")
  if (!tbody) return

  if (!users.length) {
    tbody.innerHTML = `<tr><td colspan="5">
      <div class="empty-state"><div class="empty-icon">👤</div><p>Sin usuarios registrados.</p></div>
    </td></tr>`
    return
  }

  tbody.innerHTML = users.map(u => `
    <tr>
      <td>${u.id || "—"}</td>
      <td>${u.name || "—"}</td>
      <td>${u.username}</td>
      <td><span class="badge badge-${u.role}">${u.role}</span></td>
      <td>
        <div class="td-actions">
         ${u.role !== "admin" ? `<button class="btn btn-secondary btn-sm" onclick="openEditUser('${u.uid}')">Editar</button>` : ""}
          ${u.role !== "admin" ? `<button class="btn btn-danger btn-sm" onclick="confirmDeleteUser('${u.uid}', '${u.username}')">Eliminar</button>` : ""}
        </div>
        </div>
      </td>
    </tr>`).join("")
}

// ── Admin: edit user modal ──────────────────────────────────────
let _allUsers = []
window.openEditUser = function(uid) {
  const u = _allUsers.find(x => x.uid === uid)
  if (!u) return
  document.getElementById("editUid").value      = uid
  document.getElementById("editId").value       = u.id       || ""
  document.getElementById("editName").value     = u.name     || ""
  document.getElementById("editUsername").value = u.username || ""
  document.getElementById("editRole").value     = u.role     || "user"
  document.getElementById("editPassword").value = ""
  document.getElementById("editModal").classList.remove("hidden")
}

window.closeEditModal = function() {
  document.getElementById("editModal").classList.add("hidden")
}

window.confirmDeleteUser = function(uid, username) {
  if (!confirm(`¿Eliminar al usuario "${username}"? Esta acción no se puede deshacer.`)) return
  deleteUser(uid)
    .then(() => showToast("Usuario eliminado.", "success"))
    .catch(err => showToast(err.message, "error"))
}

// ── User: render tasks table ────────────────────────────────────
function renderTareasTable(tareas) {
  const tbody = document.getElementById("tareasTableBody")
  if (!tbody) return

  if (!tareas.length) {
    tbody.innerHTML = `<tr><td colspan="5">
      <div class="empty-state"><div class="empty-icon">📋</div><p>Sin tareas registradas.</p></div>
    </td></tr>`
    return
  }

  tbody.innerHTML = tareas.map(t => `
    <tr>
      <td>${t.titulo}</td>
      <td>${t.descripcion || "—"}</td>
      <td>${t.fechaLimite || "—"}</td>
      <td><span class="priority priority-${t.prioridad}">${t.prioridad}</span></td>
      <td>
        <div class="td-actions">
          <button class="btn btn-danger btn-sm btn-icon" title="Eliminar"
            onclick="confirmDeleteTarea('${t.key}')">✕</button>
        </div>
      </td>
    </tr>`).join("")
}

window.confirmDeleteTarea = function(key) {
  if (!confirm("¿Eliminar esta tarea?")) return
  deleteTarea(key)
    .then(() => showToast("Tarea eliminada.", "success"))
    .catch(err => showToast(err.message, "error"))
}

// ── Console init ─────────────────────────────────────────────────
function initConsolePage() {
  const session = getSession()
  if (!session) {
    window.location.href = "index.html"
    return
  }

  const { uid, user, role } = session

  // ── Fill user chip ────────────────────────────────────────────
  const initials = (user.name || user.username || "?")
    .split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase()
  document.getElementById("userAvatar").textContent = initials
  document.getElementById("userName").textContent   = user.name || user.username
  document.getElementById("userRole").textContent   = role

  const roleBadge = document.getElementById("roleBadge")
  roleBadge.textContent = role
  roleBadge.className = `badge badge-${role}`

  // ── Render nav & modules by role ─────────────────────────────
  const nav     = document.getElementById("sidebarNav")
  const content = document.getElementById("moduleContent")

  if (role === "admin") {
    nav.innerHTML = `
      <div class="nav-section-title">Administración</div>
      <li class="nav-item active" data-module="mod-usuarios" onclick="activateModule('mod-usuarios')">
        <span class="nav-icon">👥</span>
        <span class="nav-label">Usuarios</span>
      </li>`

    content.innerHTML = `
      <!-- ── MÓDULO USUARIOS ── -->
      <div id="mod-usuarios" class="module-panel active">
        <div class="panel-header">
          <div>
            <h2>Gestión de Usuarios</h2>
            <p>Administra los usuarios del sistema</p>
          </div>
        </div>

        <!-- Add user form -->
        <div class="card">
          <div class="card-title">Agregar usuario</div>
          <form id="Addusers">
            <div class="form-grid">
              <div class="field">
                <label for="add-id">ID</label>
                <input type="text" id="add-id" name="id" placeholder="001" required>
              </div>
              <div class="field">
                <label for="add-name">Nombre</label>
                <input type="text" id="add-name" name="name" placeholder="Juan Pérez" required>
              </div>
              <div class="field">
                <label for="add-username">Username</label>
                <input type="text" id="add-username" name="username" placeholder="juanperez" required>
              </div>
              <div class="field">
                <label for="add-password">Contraseña</label>
                <input type="password" id="add-password" name="password" placeholder="••••••••" required>
              </div>
              <div class="field">
                <label for="add-role">Rol</label>
                <select id="add-role" name="role" required>
                  <option value="admin">Admin</option>
                  <option value="user" selected>User</option>
                </select>
              </div>
            </div>
            <div class="form-actions">
              <button type="submit" class="btn btn-primary" style="width:auto">
                <span id="addBtnText">Agregar usuario</span>
                <span id="addBtnSpinner" class="spinner" style="display:none"></span>
              </button>
              <button type="reset" class="btn btn-secondary">Limpiar</button>
            </div>
          </form>
        </div>

        <!-- Users list -->
        <div class="card">
          <div class="card-title">Lista de usuarios</div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th><th>Nombre</th><th>Username</th><th>Rol</th><th>Acciones</th>
                </tr>
              </thead>
              <tbody id="usersTableBody">
                <tr><td colspan="5"><div class="empty-state">
                  <div class="spinner"></div>
                </div></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ── EDIT MODAL ── -->
      <div id="editModal" class="modal-overlay hidden">
        <div class="modal">
          <div class="modal-header">
            <h3>Editar usuario</h3>
            <button class="modal-close" onclick="closeEditModal()">✕</button>
          </div>
          <form id="editUserForm">
            <input type="hidden" id="editUid">
            <div class="form-grid">
              <div class="field">
                <label for="editId">ID</label>
                <input type="text" id="editId" required>
              </div>
              <div class="field">
                <label for="editName">Nombre</label>
                <input type="text" id="editName" required>
              </div>
              <div class="field">
                <label for="editUsername">Username</label>
                <input type="text" id="editUsername" required>
              </div>
              <div class="field">
                <label for="editPassword">Nueva contraseña</label>
                <input type="password" id="editPassword" placeholder="Dejar vacío para no cambiar">
              </div>
              <div class="field">
                <label for="editRole">Rol</label>
                <select id="editRole">
                  <option value="admin">Admin</option>
                  <option value="user">User</option>
                </select>
              </div>
            </div>
            <div class="form-actions">
              <button type="submit" class="btn btn-primary" style="width:auto">Guardar cambios</button>
              <button type="button" class="btn btn-secondary" onclick="closeEditModal()">Cancelar</button>
            </div>
          </form>
        </div>
      </div>`

    // ── Subscribe users ────────────────────────────────────────
    subscribeUsers(users => {
      _allUsers = users
      renderUsersTable(users,role)
    })

    // ── Add user submit ────────────────────────────────────────
    document.getElementById("Addusers").addEventListener("submit", async e => {
      e.preventDefault()
      const btnText = document.getElementById("addBtnText")
      const spinner = document.getElementById("addBtnSpinner")
      btnText.textContent = "Guardando…"
      spinner.style.display = "inline-block"

      try {
        await addUser({
          id:       document.getElementById("add-id").value.trim(),
          name:     document.getElementById("add-name").value.trim(),
          username: document.getElementById("add-username").value.trim(),
          password: document.getElementById("add-password").value,
          role:     document.getElementById("add-role").value
        })
        e.target.reset()
        showToast("Usuario agregado correctamente.", "success")
      } catch (err) {
        showToast(err.message, "error")
      } finally {
        btnText.textContent = "Agregar usuario"
        spinner.style.display = "none"
      }
    })

    // ── Edit user submit ───────────────────────────────────────
    document.getElementById("editUserForm").addEventListener("submit", async e => {
      e.preventDefault()
      try {
        await updateUser(document.getElementById("editUid").value, {
          id:       document.getElementById("editId").value.trim(),
          name:     document.getElementById("editName").value.trim(),
          username: document.getElementById("editUsername").value.trim(),
          password: document.getElementById("editPassword").value,
          role:     document.getElementById("editRole").value
        })
        closeEditModal()
        showToast("Usuario actualizado.", "success")
      } catch (err) {
        showToast(err.message, "error")
      }
    })

  } else {
    // ── ROLE: user ──────────────────────────────────────────────
    nav.innerHTML = `
      <div class="nav-section-title">Mi espacio</div>
      <li class="nav-item active" data-module="mod-tareas" onclick="activateModule('mod-tareas')">
        <span class="nav-icon">📋</span>
        <span class="nav-label">Tareas</span>
      </li>`

    content.innerHTML = `
      <!-- ── MÓDULO TAREAS ── -->
      <div id="mod-tareas" class="module-panel active">
        <div class="panel-header">
          <div>
            <h2>Mis Tareas</h2>
            <p>Organiza y gestiona tu trabajo</p>
          </div>
        </div>

        <!-- Add task form -->
        <div class="card">
          <div class="card-title">Nueva tarea</div>
          <form id="AddTareas">
            <div class="form-grid">
              <div class="field" style="grid-column: 1/-1">
                <label for="tarea-titulo">Título</label>
                <input type="text" id="tarea-titulo" placeholder="Nombre de la tarea" required>
              </div>
              <div class="field" style="grid-column: 1/-1">
                <label for="tarea-desc">Descripción</label>
                <textarea id="tarea-desc" placeholder="Detalla la tarea…"></textarea>
              </div>
              <div class="field">
                <label for="tarea-fecha">Fecha límite</label>
                <input type="date" id="tarea-fecha">
              </div>
              <div class="field">
                <label for="tarea-prioridad">Prioridad</label>
                <select id="tarea-prioridad" required>
                  <option value="alta">🔴 Alta</option>
                  <option value="media" selected>🟡 Media</option>
                  <option value="baja">🟢 Baja</option>
                </select>
              </div>
            </div>
            <div class="form-actions">
              <button type="submit" class="btn btn-primary" style="width:auto">
                <span id="tareaBtnText">Agregar tarea</span>
                <span id="tareaBtnSpinner" class="spinner" style="display:none"></span>
              </button>
              <button type="reset" class="btn btn-secondary">Limpiar</button>
            </div>
          </form>
        </div>

        <!-- Tasks list -->
        <div class="card">
          <div class="card-title">Lista de tareas</div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Título</th><th>Descripción</th><th>Fecha límite</th>
                  <th>Prioridad</th><th>Acción</th>
                </tr>
              </thead>
              <tbody id="tareasTableBody">
                <tr><td colspan="5"><div class="empty-state">
                  <div class="spinner"></div>
                </div></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>`

    // ── Subscribe tasks ────────────────────────────────────────
    subscribeTareas(uid, renderTareasTable)

    // ── Add task submit ────────────────────────────────────────
    document.getElementById("AddTareas").addEventListener("submit", async e => {
      e.preventDefault()
      const btnText = document.getElementById("tareaBtnText")
      const spinner = document.getElementById("tareaBtnSpinner")
      btnText.textContent = "Guardando…"
      spinner.style.display = "inline-block"

      try {
        await addTarea({
          titulo:      document.getElementById("tarea-titulo").value.trim(),
          descripcion: document.getElementById("tarea-desc").value.trim(),
          fechaLimite: document.getElementById("tarea-fecha").value,
          prioridad:   document.getElementById("tarea-prioridad").value,
          ownerUid:    uid,
          ownerName:   user.name || user.username
        })
        e.target.reset()
        showToast("Tarea agregada.", "success")
      } catch (err) {
        showToast(err.message, "error")
      } finally {
        btnText.textContent = "Agregar tarea"
        spinner.style.display = "none"
      }
    })
  }

  // ── Set first module as active in topBar ────────────────────
  const firstNav = document.querySelector(".nav-item")
  if (firstNav) {
    document.getElementById("topBarTitle").textContent =
      firstNav.querySelector(".nav-label")?.textContent || ""
  }

  // ── Logout ──────────────────────────────────────────────────
  document.getElementById("btnLogout").addEventListener("click", () => {
    if (confirm("¿Cerrar sesión?")) logout()
  })

  // ── Expose activateModule globally for onclick handlers ─────
  window.activateModule = activateModule
}

// ═══════════════════════════════════════════════════════════════
//  ENTRY POINT — detect page and init
// ═══════════════════════════════════════════════════════════════
const page = window.location.pathname.split("/").pop() || "index.html"

if (page === "console.html") {
  document.addEventListener("DOMContentLoaded", initConsolePage)
} else {
  document.addEventListener("DOMContentLoaded", initLoginPage)
}