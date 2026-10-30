/* درمان‌گر Web Push service worker */
self.addEventListener('push', event => {
  let data = { title: 'درمان‌گر', body: 'اعلان جدید دارید.', url: '/' };
  try { if (event.data) data = { ...data, ...event.data.json() }; } catch {}
  event.waitUntil(self.registration.showNotification(data.title || 'درمان‌گر', {
    body: data.body || 'اعلان جدید دارید.',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    data: { url: data.url || '/' },
    renotify: false
  }));
});
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target = new URL(event.notification.data?.url || '/', self.location.origin).href;
  event.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const client of list) if (client.url.startsWith(self.location.origin) && 'focus' in client) { client.navigate(target); return client.focus(); }
    return clients.openWindow(target);
  }));
});
