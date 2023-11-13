const openbutton = document.querySelector("[open-modal]")
const closebutton = document.querySelector("[close-modal]")
const modal = document.querySelector("[reset]")

openbutton.addEventListener("click", () => {
    modal.showModal()
})

closebutton.addEventListener("click", () => {
    modal.close()
})

