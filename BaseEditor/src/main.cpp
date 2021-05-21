#include "BaseEditor.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    BaseEditor w;
    w.show();
    return a.exec();
}
