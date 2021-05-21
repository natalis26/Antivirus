#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_Client.h"
#include <Windows.h>
#include <IPC.h>
#include <ThreatList.h>

class Client : public QMainWindow
{
    Q_OBJECT

public:
    Client(QWidget *parent = Q_NULLPTR);
    ~Client();

private:
    void connectToServer();
    void wakeUpServer();
    void scanRequest();
    void deleteRequest(uint64_t index);
    void quarantineRequest(uint64_t index);
    void unQuarantineRequest(uint64_t index);
    void setupMonitor(const std::u16string& path);
    void loadMonitors();
    void loadScanners();

signals:
    void reportOutput(const QString& value);
    void setProgressBar(int value);
    void removeItem(int index);

private slots:
    void on_browseButton_clicked();
    void on_scanButton_clicked();
    void on_stopScanButton_clicked();
    void on_reportButton_clicked();
    void on_shutDownButton_clicked();
    void on_schedulePageButton_clicked();
    void on_monitorPageButton_clicked();

    void on_backButton_clicked();
    void on_deleteButton_clicked();
    void on_quarantineButton_clicked();
    void on_unQuarantineButton_clicked();


    void on_monitorButton_clicked();
    void on_stopMonitorButton_clicked();
    void on_monitorBackButton_clicked();
    void on_monitorBrowseButton_clicked();

    void on_scheduleScanButton_clicked();
    void on_scheduleBackButton_clicked();
    void on_cancelScheduleScanButton_clicked();
    void on_scheduleBrowseButton_clicked();



private:
    Ui::ClientClass ui;
    std::unique_ptr<ThreatList> threats;
    std::shared_ptr<IPC> ipc;
    std::shared_ptr<IPC> scanIpc;
    QThread* scanThread;
};
