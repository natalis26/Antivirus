#include <QFileDialog>
#include <sstream>
#include <picosha2.h>

#include "BaseEditor.h"
#include "IPC.h"
#include "BinaryReader.h"
#include "BinaryWriter.h"


static std::vector<uint8_t> HexToBytes(const std::string& hex) {
	std::vector<uint8_t> bytes;

	for (unsigned int i = 0; i < hex.length(); i += 2) {
		std::string byteString = hex.substr(i, 2);
		uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

static bool IsHexString(const std::string& str)
{
	for (auto character : str)
	{
		if (!std::isxdigit(character))
			return false;
	}
	return true;
}


BaseEditor::BaseEditor(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    ui.tableWidget->horizontalHeader()->setStretchLastSection(true);
	connect(ui.tableWidget, &QTableWidget::cellChanged, this, &BaseEditor::cellChanged);
}

void BaseEditor::read(const std::u16string& path)
{
	BinaryReader reader(path);

	std::u16string header = reader.readU16String();
	if (header != std::u16string(u"Denisovich"))
		return;

	uint64_t rowCount = reader.readUInt64();

	ui.tableWidget->setRowCount(rowCount);
	
	for (int i = 0; i < rowCount; i++)
	{

		ui.tableWidget->setItem(i, 0, new QTableWidgetItem(
			QString::fromUtf16(reader.readU16String().c_str())));

		ui.tableWidget->setItem(i, 1, new QTableWidgetItem(
			QString::fromUtf16(reader.readU16String().c_str())));

		uint64_t length = reader.readUInt64();

		// display signature in hex
		std::stringstream toHex;
		uint64_t sigStart = reader.readUInt64();
		toHex << std::hex << sigStart;
		
		std::string hex = toHex.str();
		if (hex.size() % 2 != 0)
			hex = "0" + hex;

		ui.tableWidget->setItem(i, 3, new QTableWidgetItem(hex.c_str()));

		ui.tableWidget->setItem(i, 2, new QTableWidgetItem(QString::number(length)));
		ui.tableWidget->setItem(i, 4, new QTableWidgetItem(QString::number(reader.readUInt64())));
		ui.tableWidget->setItem(i, 5, new QTableWidgetItem(QString::number(reader.readUInt64())));
		ui.tableWidget->setItem(i, 6, new QTableWidgetItem(QString(reader.readASCIIString().c_str())));
	}

	reader.close();
}


void BaseEditor::write(const std::u16string& path)
{
	BinaryWriter writer(path);

	std::u16string header(u"Denisovich");

	writer.writeU16String(header);
	writer.writeUInt64((uint64_t)ui.tableWidget->rowCount());

	for (int i = 0; i < ui.tableWidget->rowCount(); i++)
	{
		std::u16string name = ui.tableWidget->item(i, 0)->data(Qt::DisplayRole).toString().toStdU16String();
		std::u16string type = ui.tableWidget->item(i, 1)->data(Qt::DisplayRole).toString().toStdU16String();
		std::string hash = ui.tableWidget->item(i, 6)->data(Qt::DisplayRole).toString().toStdString();

		writer.writeU16String(name);
		writer.writeU16String(type);
		writer.writeUInt64(ui.tableWidget->item(i, 2)->data(Qt::DisplayRole).toULongLong());

		QString hex = ui.tableWidget->item(i, 3)->data(Qt::DisplayRole).toString();
		bool success;
		uint64_t sigStart = hex.toULongLong(&success, 16);

		writer.writeUInt64(sigStart);
		writer.writeUInt64(ui.tableWidget->item(i, 4)->data(Qt::DisplayRole).toULongLong());
		writer.writeUInt64(ui.tableWidget->item(i, 5)->data(Qt::DisplayRole).toULongLong());
		writer.writeASCIIString(hash);
	}
	writer.close();
}

void BaseEditor::on_pathButton_clicked()
{
	QFileDialog* dialog = new QFileDialog(nullptr, "OpenFileDialog", "./", "*.lsd");
	dialog->show();
	if (dialog->exec())
		ui.pathLineEdit->setText(dialog->selectedFiles()[0]);
}

void BaseEditor::on_writeButton_clicked()
{
	write(ui.pathLineEdit->text().toStdU16String());
}

void BaseEditor::on_readButton_clicked()
{
	read(ui.pathLineEdit->text().toStdU16String());
}

void BaseEditor::on_addButton_clicked()
{
	ui.tableWidget->setRowCount(ui.tableWidget->rowCount() + 1);
}

void BaseEditor::on_deleteButton_clicked()
{
	ui.tableWidget->setRowCount(ui.tableWidget->rowCount() - 1);
}

// signature adding algorithm
void BaseEditor::cellChanged(int row, int column)
{
	// if not signature start field
	if (column != 3)
		return;


	if (ui.tableWidget->item(row, column)->text().isEmpty())
	{
		ui.tableWidget->item(row, column)->setText("");
		return;
	}

	std::string cellValue;
	try
	{
		cellValue = ui.tableWidget->item(row, column)->data(Qt::DisplayRole).toString().toStdString();

		// remove whitespaces
		cellValue.erase(remove_if(cellValue.begin(), cellValue.end(), isspace), cellValue.end());

		// signatures with length less than 8 bytes are not allowed
		uint64_t length = cellValue.size();
		if (cellValue.size() < 16)
		{
			ui.tableWidget->item(row, column)->setText("");
			ui.tableWidget->setItem(row, 2, new QTableWidgetItem(""));
			ui.tableWidget->setItem(row, 6, new QTableWidgetItem(""));
			return;
		}
		
		// signature should be hex string
		if (!IsHexString(cellValue))
		{
			ui.tableWidget->item(row, column)->setText("");
			ui.tableWidget->setItem(row, 2, new QTableWidgetItem(""));
			ui.tableWidget->setItem(row, 6, new QTableWidgetItem(""));
			return;
		}

		// if no additional bytes
		if (length == 16)
		{
			ui.tableWidget->setItem(row, 2, new QTableWidgetItem(QString::number(length / 2)));
			ui.tableWidget->setItem(row, 6, new QTableWidgetItem("No hash"));
			return;
		}

		
		// set sigStart field to first 8 bytes
		ui.tableWidget->setItem(row, column, new QTableWidgetItem(cellValue.substr(0, 16).c_str()));

		// modify length field
		ui.tableWidget->setItem(row, 2, new QTableWidgetItem(QString::number(length / 2)));

		// calculate hash for the rest of the bytes
		cellValue.erase(0, 16);

		std::vector<uint8_t> bytes = HexToBytes(cellValue);
		std::string hash_hex_str;
		picosha2::hash256_hex_string(bytes, hash_hex_str);
		ui.tableWidget->setItem(row, 6, new QTableWidgetItem(hash_hex_str.c_str()));
	}
	catch (...)
	{
		ui.tableWidget->item(row, column)->setText("");
		ui.tableWidget->item(row, 2)->setText("");
		ui.tableWidget->item(row, 6)->setText("");
	}

}


