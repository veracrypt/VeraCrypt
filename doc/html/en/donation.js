document.addEventListener('DOMContentLoaded', function() {  
    document.getElementById('currency-form').addEventListener('submit', function(e) {  
        e.preventDefault();  
        const select = this.querySelector('select');  
        if (select.value) {  
            window.open(select.value, '_blank');  
        }  
    });  
});
