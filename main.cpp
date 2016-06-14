#include "main.h"
#include "shapture.h"
#include "stdio.h"
#include <string>
#include <pthread.h>
#include <sstream>

QString s2q(const std::string &s){
    return QString(QString::fromLocal8Bit(s.c_str()));
}
std::string q2s(const QString &s){
    return std::string((const char *)s.toLocal8Bit());
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

std::string& trim(std::string &s) 
{
    if (s.empty()) {
        return s;
    }
    s.erase(0,s.find_first_not_of(" "));
    s.erase(s.find_last_not_of(" ") + 1);
    return s;
}


mainWin::mainWin(QMainWindow *parent):QMainWindow(parent){
    setupUi(this);
    this->on_off->setText("on");
    this->tableWidget->setColumnCount(4);
    this->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    QHeaderView *headerView = this->tableWidget->verticalHeader();
    headerView->setHidden(true);  
    QStringList headers; 
    headers << "No." << "src_ip" << "des_ip" << "proto";
    this->tableWidget->setHorizontalHeaderLabels(headers);
    this->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);  
    this->tableWidget->horizontalHeader()->setStretchLastSection(true);
    this->tableWidget->horizontalHeader()->setResizeMode(QHeaderView::Stretch);
    this->running = false;
    QObject::connect(this->on_off, SIGNAL(released()),this, SLOT(handle_on_off()));
    QObject::connect(this->filter, SIGNAL(released()),this, SLOT(handle_filter()));
    QObject::connect(this->tableWidget, SIGNAL(cellClicked(int, int) ), this, SLOT(handle_rowselection(int,int)));
}

void mainWin::addItem(int row, int column, QString content){
      QTableWidgetItem *item = new QTableWidgetItem (content);
      this->tableWidget->setItem(row, column, item);
} 

void mainWin::add(int number, std::string src_ip, std::string des_ip, std::string proto){
    int rowIndex = this->tableWidget->rowCount();
    this->tableWidget->setRowCount(rowIndex+1);
    //this->tableWidget->insertRow(rowIndex);
    //rowIndex = this->tableWidget->rowCount();
    char tmp[10];
    sprintf(tmp,"%d",number);
    this->addItem(rowIndex, 0, s2q(std::string(tmp)));
    this->addItem(rowIndex, 1, s2q(src_ip));
    this->addItem(rowIndex, 2, s2q(des_ip));
    this->addItem(rowIndex, 3, s2q(proto));
    if(this->is_filtered(number, src_ip, des_ip, proto))
        this->tableWidget->setRowHidden(rowIndex, true); 
}

void mainWin::update(pack_dcp msg){
    this->vec.push_back(msg);
    this->add(msg.no, msg.srcip, msg.desip, msg.getProto());
}

void mainWin::handle_on_off(){
    std::string adpt = q2s(this->adp->text());
    if(this->running)
        this->on_off->setText("on");
    else 
        this->on_off->setText("off");
    this->running = !this->running;

    emit switch_on_off(adpt);
}

void mainWin::handle_rowselection(int row, int col){
    this->textBrowser->setText(s2q(this->vec[row].content));
}

void mainWin::handle_filter(){
    std::string rule = q2s(lineEdit->text());
    std::vector<std::string> elems = split(rule, '|');
    for (int i = 0 ; i < 4 ; i ++) this->mask[i] = 0;

    for (int i = 0 ; i < elems.size(); ++i){
        std::vector<std::string> tmp = split(trim(elems[i]),'=');
        if (tmp[0] == "src_ip"){
            this->mask[1] = 1;
            this->fil[1] = tmp[1];
        }else if (tmp[0] == "des_ip"){
            this->mask[2] = 1;
            this->fil[2] = tmp[1];
        }else if(tmp[0] == "proto"){
            this->mask[3] = 1;
            this->fil[3] = tmp[1];
        }
    }

    for( int i = 0; i < this->tableWidget->rowCount(); ++i ){
        bool match = true;
        for( int j = 0; j < this->tableWidget->columnCount(); ++j ){
            QTableWidgetItem *item = this->tableWidget->item( i, j );
            std::string sss = q2s(item->text());
            if(this->mask[j] && sss != this->fil[j])
                match = false;
        }
        this->tableWidget->setRowHidden(i, !match );
    }
}

bool mainWin::is_filtered(int no, std::string src_ip, std::string des_ip, std::string proto){
    if (this->mask[1] && src_ip != this->fil[1])
        return false;
    else if(this->mask[2] && des_ip != this->fil[2])
        return false;
    else if(this->mask[3] && proto != this->fil[3])
        return false;
    return true;
}

int main(int argc, char **argv){
    qRegisterMetaType<pack_dcp>("pack_dcp");
    qRegisterMetaType<pack_dcp>("pack_dcp&");
    QApplication app(argc, argv);
    mainWin sha;
    Core core;
    QObject::connect(&core, SIGNAL(newpack(pack_dcp)),
                     &sha, SLOT(update(pack_dcp)));
    QObject::connect(&sha, SIGNAL(switch_on_off(std::string)),
                     &core, SLOT(handle_switch(std::string)));
    sha.show();
    //core.start();
    return app.exec();
}
