async function clickPagesSequentially(pages) {
    for (const page of pages) {
        await new Promise(resolve => setTimeout(resolve, 3100));
        page.click();
    }
}

const pages = document.querySelectorAll('.page');
clickPagesSequentially(pages);