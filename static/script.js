// Scripts JavaScript para mejorar la funcionalidad de las páginas
// Por ejemplo, validación de formularios
document.addEventListener('DOMContentLoaded', function() {
    var form = document.querySelector('form');
    form.addEventListener('submit', function(event) {
        var username = document.getElementById('username').value;
        var password = document.getElementById('password').value;
        if (username === '' || password === '') {
            alert('Please fill in all fields.');
            event.preventDefault();
        }
    });
});
