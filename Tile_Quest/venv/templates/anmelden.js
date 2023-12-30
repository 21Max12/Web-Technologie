const openbutton = document.querySelector("[open-create]")
const closebutton = document.querySelector("[close-create]")
const modal = document.querySelector("[anmelden]")

openbutton.addEventListener("click", () => {
    modal.showModal()
})

closebutton.addEventListener("click", () => {
    modal.close()
})

