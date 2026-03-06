## To do List
[] Leer Users desde Firebase Realtime Database
[] Función hashPassword() con PBKDF2 + SHA-256 (ya existe, la integraré)
[] Función verifyPassword(input, storedHash, storedSalt) para comparar el hash
[] Función loginUser(username, password) → retorna { user, role } o error
[] Al login exitoso → guardar en sessionStorage y redirigir a console.html
[] En console.html → leer sesión, renderizar menú según rol
[] Módulo Admin: CRUD completo de usuarios (agregar, editar, eliminar, listar)
[] Módulo User: Formulario de tareas → crear referencia Tareas en Firebase
[] Función para agregar tareas asociadas al usuario logueado

[]styles.css

[] Layout con sidebar + header empresarial
[] Estilos para formularios, tablas, botones modernos
[] Responsive básico

## ✅ Lo que se implementó
scripts.js

verifyPassword() — descompone saltHex:hashHex, rehashea con PBKDF2 y hace comparación en tiempo constante
loginUser() — busca el usuario en Firebase, verifica credenciales y retorna { uid, user, role }
saveSession / getSession / logout — gestión de sesión con sessionStorage
CRUD completo de usuarios (addUser, updateUser, deleteUser, subscribeUsers)
Módulo de tareas (addTarea, deleteTarea, subscribeTareas) — crea el nodo Tareas en Firebase
Auto-detección de página (index.html vs console.html) para inicializar el módulo correcto

index.html — Login con manejo de errores, spinner y redirección automática si ya hay sesión
console.html — Shell limpia; todo el contenido (menú + módulos) se inyecta dinámicamente según el rol
styles.css — Diseño oscuro empresarial con Syne + DM Sans, sidebar fija, tablas, toasts, modal de edición y badges de prioridad