#include <QString>
#include <QFileDialog>
#include <QInputDialog>
#include <QThread>
#include <QProgressBar>

#include <IPC.h>
#include <IPCMailslot.h>
#include <BinaryReader.h>
#include <BinaryWriter.h>
#include <TlHelp32.h>
#include <QTime>
#include "Client.h"

#include "FileDialog.h"

#define SVCNAME TEXT("Denisovich Anti-Virus")

Client::Client(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
	ui.scanProgressBar->hide();
	QHeaderView* monitorTableHeaderView = ui.monitorTable->horizontalHeader();
	monitorTableHeaderView->setSectionResizeMode(0, QHeaderView::Stretch);
	QHeaderView* scheduleTableHeaderView = ui.scheduleScanTable->horizontalHeader();
	scheduleTableHeaderView->setSectionResizeMode(0, QHeaderView::Stretch);

	connect(this, &Client::reportOutput, ui.reportTextEdit, &QTextEdit::append);
	connect(this, &Client::setProgressBar, ui.scanProgressBar, &QProgressBar::setValue);
	connect(this, &Client::removeItem, ui.threatList, &QListWidget::takeItem);
	connectToServer();
	threats = std::make_unique<ThreatList>(u"Threats.lsd");
	loadMonitors();
	loadScanners();
}

Client::~Client()
{
	BinaryWriter reader(ipc);
	reader.writeUInt8((uint8_t)CMDCODE::CLIENTSHUTDOWN);
}

void Client::on_scanButton_clicked()
{
	ui.reportTextEdit->setText("Scanning in progress...");
	ui.scanProgressBar->setValue(0);
	ui.scanProgressBar->show();
	scanThread = QThread::create(&Client::scanRequest, this);
	scanThread->start();
}

void Client::on_browseButton_clicked()
{
	FileDialog* dialog = new FileDialog(nullptr);
	dialog->setFileMode(QFileDialog::Directory);
	dialog->show();

	if (dialog->exec())
		ui.pathLineEdit->setText(dialog->selectedFiles()[0]);
}

void Client::on_shutDownButton_clicked()
{
	BinaryWriter reader(ipc);
	reader.writeUInt8((uint8_t)CMDCODE::SERVERSHUTDOWN);
	QCoreApplication::quit();
}


void Client::on_schedulePageButton_clicked()
{
	ui.stackedWidget->setCurrentIndex(3);
}

void Client::on_monitorPageButton_clicked()
{
	ui.stackedWidget->setCurrentIndex(2);
}

void Client::on_reportButton_clicked()
{
	threats->load();

	ui.threatList->clear();
	for (size_t i = 0; i < threats->size(); i++)
	{
		ui.threatList->addItem(QString::fromUtf16(threats->get(i).c_str()));
	}

	ui.stackedWidget->setCurrentIndex(1);
}

void Client::on_backButton_clicked()
{
	ui.stackedWidget->setCurrentIndex(0);
}

void Client::on_deleteButton_clicked()
{
	if (ui.threatList->selectedItems().empty())
		return;

	uint64_t index = ui.threatList->row(ui.threatList->selectedItems()[0]);
	QThread* deleteThread = QThread::create(&Client::deleteRequest, this, index);
	deleteThread->start();
}


void Client::on_quarantineButton_clicked()
{
	uint64_t index = ui.threatList->row(ui.threatList->selectedItems()[0]);
	QThread* quarantineThread = QThread::create(&Client::quarantineRequest, this, index);
	quarantineThread->start();
}

void Client::on_unQuarantineButton_clicked()
{
	uint64_t index = ui.threatList->row(ui.threatList->selectedItems()[0]);
	QThread* unQuarantineThread = QThread::create(&Client::unQuarantineRequest, this, index);
	unQuarantineThread->start();
}

void Client::on_monitorButton_clicked()
{
	QThread* monitorSetupThread = QThread::create(&Client::setupMonitor, this, ui.monitorPathEdit->text().toStdU16String());
	monitorSetupThread->start();

	ui.monitorTable->setRowCount(ui.monitorTable->rowCount() + 1);

	int lastIndex = ui.monitorTable->rowCount() - 1;
	ui.monitorTable->setItem(lastIndex, 0, new QTableWidgetItem(ui.monitorPathEdit->text()));
}

void Client::on_stopScanButton_clicked()
{
	scanThread->terminate();
	scanThread->wait();

	BinaryWriter writer(ipc);

	writer.writeUInt8((uint8_t)CMDCODE::STOPSCAN);
	

	BinaryReader reader(ipc);
	bool success = (bool)reader.readUInt8();


	if (success)
	{
		reportOutput("Scanning stopped");
	}
}

void Client::on_stopMonitorButton_clicked()
{
	if (ui.monitorTable->selectedItems().empty())
		return;

	uint64_t index = ui.monitorTable->row(ui.monitorTable->selectedItems()[0]);

	ui.monitorTable->removeRow(index);

	BinaryWriter writer(ipc);

	writer.writeUInt8((uint8_t)CMDCODE::STOPMONITOR);
	writer.writeUInt64(index);
}

void Client::on_monitorBackButton_clicked()
{
	ui.stackedWidget->setCurrentIndex(0);
}

void Client::on_monitorBrowseButton_clicked()
{
	FileDialog* dialog = new FileDialog(nullptr);
	dialog->setFileMode(QFileDialog::Directory);
	dialog->show();

	if (dialog->exec())
		ui.monitorPathEdit->setText(dialog->selectedFiles()[0]);
}

void Client::on_scheduleScanButton_clicked()
{
	BinaryWriter writer(ipc);
	writer.writeUInt8((uint8_t)CMDCODE::SCHEDULESCAN);
		
	writer.writeU16String(ui.schedulePathEdit->text().toStdU16String());
	uint32_t hours = (uint32_t)(ui.scheduleTimeEdit->time().hour());
	uint32_t minutes = (uint32_t)(ui.scheduleTimeEdit->time().minute());
	writer.writeUInt32(hours);
	writer.writeUInt32(minutes);


	ui.scheduleScanTable->setRowCount(ui.scheduleScanTable->rowCount() + 1);

	int lastIndex = ui.scheduleScanTable->rowCount() - 1;
	ui.scheduleScanTable->setItem(lastIndex, 0, new QTableWidgetItem(ui.schedulePathEdit->text()));

	QString time = QString::number(hours) + QString(":") + QString::number(minutes);
	ui.scheduleScanTable->setItem(lastIndex, 1, new QTableWidgetItem(time));
}

void Client::on_scheduleBackButton_clicked()
{
	ui.stackedWidget->setCurrentIndex(0);
}

void Client::on_cancelScheduleScanButton_clicked()
{
	if (ui.scheduleScanTable->selectedItems().empty())
		return;

	uint64_t index = ui.scheduleScanTable->row(ui.scheduleScanTable->selectedItems()[0]);

	BinaryWriter writer(ipc);
	writer.writeUInt8((uint8_t)CMDCODE::CANCELSCHEDULESCAN);
	writer.writeUInt64(index);

	ui.scheduleScanTable->removeRow(index);
}

void Client::on_scheduleBrowseButton_clicked()
{
	FileDialog* dialog = new FileDialog(nullptr);
	dialog->setFileMode(QFileDialog::Directory);
	dialog->show();

	if (dialog->exec())
		ui.schedulePathEdit->setText(dialog->selectedFiles()[0]);
}

void Client::connectToServer()
{
	wakeUpServer();

	ipc = IPC::Mailslots(u"\\\\.\\mailslot\\client", u"\\\\.\\mailslot\\server");

	ipc->connect();
}


void Client::scanRequest()
{
	BinaryWriter writer(ipc);
	scanIpc.reset();
	scanIpc = IPC::Mailslots(u"\\\\.\\mailslot\\clientScan", u"\\\\.\\mailslot\\server");
	BinaryReader reader(scanIpc);

	writer.writeUInt8((uint8_t)CMDCODE::SCAN);
	writer.writeU16String(ui.pathLineEdit->text().toStdU16String());
	writer.writeU16String(u"\\\\.\\mailslot\\clientScan");

	uint64_t fileCount = reader.readUInt64();
	uint64_t scannedFilesCount = 0;

	for (uint64_t i = 0; i < fileCount; i++)
	{
		std::u16string path = reader.readU16String();
		bool safe = reader.readUInt8();
		if (!safe)
		{
			std::u16string virusName = reader.readU16String();

			QString report = QString::fromUtf16(path.c_str()) + QString(" found ") + QString::fromUtf16(virusName.c_str());
			reportOutput(report);
		}
		else
		{
			QString report = QString::fromUtf16(path.c_str()) + QString(" is safe");
			reportOutput(report);
		}

		scannedFilesCount++;
		
		int percents = (scannedFilesCount / (float)fileCount) * 100;
		setProgressBar(percents);
	}
	QString report = "Total files scanned: " + QString::number(scannedFilesCount);
	reportOutput(report);
}

void Client::deleteRequest(uint64_t index)
{
	BinaryWriter writer(ipc);

	writer.writeUInt8((uint8_t)CMDCODE::DELETETHREAT);
	writer.writeUInt64(index);

	BinaryReader reader(ipc);
	bool success = (bool)reader.readUInt8();

	if (success)
	{
		threats->remove(index);
		removeItem(index);
	}
}

void Client::quarantineRequest(uint64_t index)
{
	BinaryWriter writer(ipc);

	writer.writeUInt8((uint8_t)CMDCODE::QUARANTINE);
	writer.writeUInt64(index);
}

void Client::unQuarantineRequest(uint64_t index)
{
	BinaryWriter writer(ipc);

	writer.writeUInt8((uint8_t)CMDCODE::UNQUARANTINE);
	writer.writeUInt64(index);
}

void Client::setupMonitor(const std::u16string& path)
{
	BinaryWriter writer(ipc);

	writer.writeUInt8((uint8_t)CMDCODE::MONITOR);
	writer.writeU16String(path);
}

void Client::loadMonitors()
{
	std::u16string filePath = u"Monitors.lsd";
	BinaryReader reader(filePath);
	if (!reader.isOpen())
		return;

	std::u16string header = reader.readU16String();
	if (header != u"Denisovich")
	{
		reader.close();
		return;
	}
	uint64_t recordNumber = reader.readUInt64();

	for (size_t i = 0; i < recordNumber; i++)
	{
		std::u16string scanPath = reader.readU16String();

		ui.monitorTable->setRowCount(ui.monitorTable->rowCount() + 1);

		int lastIndex = ui.monitorTable->rowCount() - 1;
		ui.monitorTable->setItem(lastIndex, 0, new QTableWidgetItem(QString::fromUtf16(scanPath.c_str())));
	}

	reader.close();
}

void Client::loadScanners()
{
	std::u16string filePath = u"Scanners.lsd";

	BinaryReader reader(filePath);
	if (!reader.isOpen())
		return;

	std::u16string header = reader.readU16String();
	if (header != u"Denisovich")
	{
		reader.close();
		return;
	}
	uint64_t recordNumber = reader.readUInt64();

	for (size_t i = 0; i < recordNumber; i++)
	{
		std::u16string scanPath = reader.readU16String();
		uint32_t hours = reader.readUInt32();
		uint32_t minutes = reader.readUInt32();

		ui.scheduleScanTable->setRowCount(ui.scheduleScanTable->rowCount() + 1);

		int lastIndex = ui.scheduleScanTable->rowCount() - 1;
		ui.scheduleScanTable->setItem(lastIndex, 0, new QTableWidgetItem(QString::fromUtf16(scanPath.c_str())));
		QString time = QString::number(hours) + QString(":") + QString::number(minutes);

		ui.scheduleScanTable->setItem(lastIndex, 1, new QTableWidgetItem(time));
	}

	reader.close();
}

void Client::wakeUpServer()
{
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_CONNECT);  

	if (NULL == schSCManager)
	{
		HRESULT error = GetLastError();
		printf("OpenSCManager failed (%d)\n", error);
		return;
	}

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		SVCNAME,            // name of service 
		SERVICE_START |
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}


	StartService(schService, NULL, NULL);
}

