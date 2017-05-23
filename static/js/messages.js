document.addEventListener('DOMContentLoaded', function () {
    'use strict';
    function dismissButton() {
        var span = document.createElement('span');
        span.appendChild(document.createTextNode('\u00d7'));
        span.title = 'Dismiss';
        span.style.cursor = 'pointer';
        span.style.float = 'right';
        span.style.fontSize = '200%';
        span.style.lineHeight = '0.7';
        span.addEventListener('click', function () {
            span.parentNode.parentNode.removeChild(span.parentNode);
        });
        return span;
    }

    window.message = function(msg, cls) {
        var p = document.createElement('p');
        p.classList.add('message');
        p.classList.add(cls);
        p.appendChild(document.createTextNode(msg));
        p.appendChild(dismissButton());
        document.querySelector('.messages').appendChild(p);
    };

    document.querySelectorAll('.message').forEach(function (msg) {
        msg.appendChild(dismissButton());
    });
});
