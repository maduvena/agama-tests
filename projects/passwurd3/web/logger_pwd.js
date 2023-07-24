var script = document['createElement']('script');
script['src'] = 'https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/2.3.1/jsencrypt.min.js';
document['head']['appendChild'](script);
var keystroke_dataP = [];
var lform = document['getElementById']('login_form');
lform['setAttribute']('autocomplete', 'off');
lform['addEventListener']('paste', (_0x6fa6x4) => {
    return _0x6fa6x4['preventDefault']()
});
var pwd = document['getElementById']('pwd');
pwd['addEventListener']('keydown', handler, false);
pwd['addEventListener']('keyup', handler, false);

function handler(_0x6fa6x7) {
    var _0x6fa6x8 = Date['now']();
    down = '';
    if (_0x6fa6x7['type'] == 'keydown') {
        down = 0
    } else {
        if (_0x6fa6x7['type'] == 'keyup') {
            down = 1
        }
    };
    keystroke_dataP['push']({
        "\x6B\x6E": _0x6fa6x7['key'],
        "\x72": down,
        "\x74\x73": _0x6fa6x8,
        "\x77\x6E": _0x6fa6x7['target']['id']
    })
}

function getKeystrokesDataP() {
    var _0x6fa6xa = JSON['stringify'](keystroke_dataP);
    keystroke_dataP = [];
    return _0x6fa6xa
}


//------------------------------------
// NEEDED IDs ARE: 
// "login_form", "pwd"
//------------------------------------

// Handle the login form submit
function gatherDataP() {
    k_pwd = getKeystrokesDataP();
    document.getElementById('k_pwd').value = k_pwd;
}
