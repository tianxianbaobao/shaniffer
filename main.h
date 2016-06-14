#ifndef MAIN_H
#define MAIN_H

#include "ui_ui.h"
#include "include/pack_dcp.h"
#include <vector>

class mainWin: public QMainWindow, private Ui_Mainwin{
    Q_OBJECT
public:
    mainWin( QMainWindow *parent=0 );
    void add(int ,std::string, std::string, std::string);
    void addItem(int, int, QString);

    std::vector<pack_dcp> vec;
signals:
    void switch_on_off(std::string);
public slots:
    void update(pack_dcp msg);
    void handle_on_off();
    void handle_rowselection(int row, int col);
    void handle_filter();
    bool is_filtered(int ,std::string, std::string , std::string);
private:
    bool running;
    std::string fil[4];
    int mask[4];
};
#endif
