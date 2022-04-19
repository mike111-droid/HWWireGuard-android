/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.hwwireguard.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;

import com.wireguard.android.R;

import androidx.core.app.NotificationCompat;

public class ForegroundService extends Service {

    @Override
    public void onCreate() {
        super.onCreate();

        try {
            // notification builder
            NotificationCompat.Builder notificationBuilder;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {

                String name="Testing";
                NotificationChannel channel = new NotificationChannel("permission_notification_channel",
                        name,
                        NotificationManager.IMPORTANCE_DEFAULT);

                ((NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE)).createNotificationChannel(channel);

                notificationBuilder = new NotificationCompat.Builder(this, "permission_notification_channel");
            } else {
                notificationBuilder = new NotificationCompat.Builder(this);
            }

            String name="Testing";

            notificationBuilder
                    .setSmallIcon(R.mipmap.ic_launcher)
                    .setContentText(name)
                    .setContentTitle("Testing")
                    .setCategory(NotificationCompat.CATEGORY_SERVICE)
                    .setOngoing(true);

            notificationBuilder.setVisibility(NotificationCompat.VISIBILITY_PRIVATE);
            //notificationBuilder.setVisibility(Notification.VISIBILITY_PUBLIC);

            Notification notification= notificationBuilder.build();

            startForeground(3, notification);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public IBinder onBind(Intent arg0) {
        return null;
    }

    @Override
    public int onStartCommand(final Intent intent, int flags, int startId) {

        if (intent!=null){
            if (intent.getAction()!=null && intent.getAction().equals("stop")) {
                killForegroundService();
                return START_STICKY;
            }
        }

        return START_STICKY;
    }

    private void killForegroundService(){
        stopForeground(true);
        stopSelf();

    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }

}