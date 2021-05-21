#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_BaseEditor.h"

class BaseEditor : public QMainWindow
{
    Q_OBJECT

public:
    BaseEditor(QWidget *parent = Q_NULLPTR);
    void read(const std::u16string& path);
    void write(const std::u16string& path);

private slots:
    void on_pathButton_clicked();
    void on_writeButton_clicked();
    void on_readButton_clicked();
    void on_addButton_clicked();
    void on_deleteButton_clicked();
    void cellChanged(int row, int column);

private:
    Ui::BaseEditorClass ui;
};
