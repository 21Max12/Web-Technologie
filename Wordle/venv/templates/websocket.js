var socket = io.connect('http://' + document.domain + ':' + location.port);
socket.on('connect', function() {
    // Bei Verbindungsaufbau
});
socket.on('spielupdate', function(data) {
    // Verarbeitung von Spielupdates
})
function submitGuess(guess) {
    var room = 'RaumID';
    socket.emit('spieleraktion', {guess: guess, room: room})
}

socket.on('spielupdate',function(data){
    console.log('Spielupdate',data);
});