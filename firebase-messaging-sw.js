importScripts('https://www.gstatic.com/firebasejs/8.3.2/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/8.3.2/firebase-messaging.js');

firebase.initializeApp({
    apiKey: "AIzaSyCpL1S5iHGCwV0dbEOgdBSmbF02bqzMlIk",
    authDomain: "pizza-queen-app.firebaseapp.com",
    projectId: "pizza-queen-app",
    storageBucket: "pizza-queen-app.firebasestorage.app",
    messagingSenderId: "824185051684",
    appId: "1:824185051684:web:9a393e31a7cf9ae6d2d6b1",
    measurementId: "G-57V0W9KQH9"
});

const messaging = firebase.messaging();
messaging.setBackgroundMessageHandler(function (payload) {
    return self.registration.showNotification(payload.data.title, {
        body: payload.data.body ? payload.data.body : '',
        icon: payload.data.icon ? payload.data.icon : ''
    });
});