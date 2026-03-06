Hola Sonnet, quisiera que hagas lo siguiente: 

Eres un senior developer. Analiza mis archivos para contexto

Edita el archivo scripts.js para que lea la base de datos en firebase, y los datos de los usuarios. 

Genera una función de js que verifique la contraseña que está encriptada en la base de datos y según el rol devuelva el usuario y su rol.  

 Dependiendo del rol, en console.html debería aparecer en menú de esta manera: 

Si es admin, en el menú debe aparecer el módulo Usuarios

En el módulo usuarios debe haber un formulario como : 

 <form id="Addusers">
            <label for="id">id:</label>
            <input type="text" id="id" name="id" required>
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" required>
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Password:</label>
            <input type="text" id="password" name="password" required>
            <label for="role">Role:</label>
            <select id="role" name="role" required>
                <option value="admin">Admin</option>
                <option value="user">User</option>
            </select>
            <button type="submit" id="submit">Add User</button>
        </form>

Si es user, en el menú debe aparecer el módulo Tareas con un form para agregar tareas. 
Genera los estilos necesarios para hacerlo moderno y empresarial en un archivo aparte css

Primero piensa la solución y haz una to do list para lo que vas a hacer, pídeme confirmación antes de crear todo. Hasta el momento solo está el objeto users en firebase, deberías crear uno nuevo que sea tareas para el rol de users. 

Haz las preguntas necesarias para mejorar el desarrollo

