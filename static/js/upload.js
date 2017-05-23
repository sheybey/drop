document.addEventListener('DOMContentLoaded', function () {
    'use strict';
    var in_progress = false;
    var form = document.querySelector('form');
    var submit = document.querySelector('input[type="submit"]');

    function start(e) {
        var x;
        var progress;

        function cancel(e) {
            e.preventDefault();
            x.abort();
        }

        function reset() {
            form.removeChild(progress);
            submit.removeEventListener('click', cancel);
            submit.addEventListener('click', start);
            submit.classList.remove('danger');
            submit.value = 'Start upload';
            in_progress = false;
        }

        e.preventDefault();

        if (in_progress) {
            return;
        }
        in_progress = true;

        progress = document.createElement('progress');
        progress.classList.add('u-cf');
        progress.classList.add('u-full-width');
        progress.indeterminate = true;

        submit.removeEventListener('click', start);
        submit.addEventListener('click', cancel);
        submit.classList.add('danger');
        submit.value = 'Cancel upload';

        form.appendChild(progress);

        x = new XMLHttpRequest();
        x.responseType = 'json';
        x.addEventListener('progress', function (e) {
            if (e.lengthComputable) {
                progress.indeterminate = false;
                progress.value = e.loaded;
                progress.max = e.total;
            } else {
                progress.indeterminate = true;
            }
        });
        x.addEventListener('load', function () {
            if (x.status === 200) {
                window.message(
                    'File `' + x.response.uploaded + '\' uploaded.',
                    'success'
                );
            } else {
                x.response.errors.forEach(function (error) {
                    window.message(error, 'error');
                });
            }
            reset();
        });
        x.addEventListener('error', function () {
            window.message('Upload failed. Try again.', 'error');
            reset();
        });
        x.addEventListener('abort', function () {
            window.message('Upload cancelled.', 'error');
            reset();
        });
        x.open('POST', window.location.pathname + '?json=true');
        x.send(new FormData(form));
    }

    form.addEventListener('submit', start);
    submit.addEventListener('click', start);
});
