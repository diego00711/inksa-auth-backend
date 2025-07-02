document.addEventListener('DOMContentLoaded', () => {
    const customSelect = document.querySelector('.custom-select-wrapper');
    const selectSelected = customSelect.querySelector('.select-selected');
    const selectItems = customSelect.querySelector('.select-items');
    const options = selectItems.querySelectorAll('div');

    // Função para abrir/fechar o dropdown
    selectSelected.addEventListener('click', (e) => {
        e.stopPropagation(); // Impede que o clique se propague para o document click handler
        selectItems.classList.toggle('select-hide');
        selectSelected.classList.toggle('select-arrow-active');
    });

    // Função para lidar com a seleção de uma opção
    options.forEach(option => {
        option.addEventListener('click', function() {
            const selectedValue = this.getAttribute('data-value');
            const selectedText = this.textContent;
            const redirectUrl = this.getAttribute('data-url');

            // Atualiza o texto exibido no campo de seleção
            selectSelected.innerHTML = selectedText + ' <i class="fas fa-chevron-down arrow"></i>';

            // Esconde a lista de opções
            selectItems.classList.add('select-hide');
            selectSelected.classList.remove('select-arrow-active');

            // Redireciona para a URL correspondente
            if (redirectUrl) {
                window.location.href = redirectUrl;
            }
        });
    });

    // Fechar o dropdown se o usuário clicar fora
    document.addEventListener('click', () => {
        if (!customSelect.contains(event.target)) {
            selectItems.classList.add('select-hide');
            selectSelected.classList.remove('select-arrow-active');
        }
    });
});