#include "main_window.hpp"
#include "theme.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#include <array>
#include <QString>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QGroupBox>
#include <QTextEdit>
#include <QTabWidget>
#include <QScrollArea>

#include "avcore/severity.hpp"
#include "avengine/engine.hpp"

namespace avdashboard {

QWidget* BuildInvestigationPage(QWidget* parent) {
    auto page = new QWidget(parent);
    auto layout = new QVBoxLayout(page);

    // Title
    auto header = theme::BuildPageHeader("Investigation Console", "Deep file inspection & VirusTotal lookup");
    layout->addWidget(header);

    // File Lookup Section
    auto fileGroupBox = new QGroupBox("File Hash Lookup", page);
    auto fileLayout = new QHBoxLayout(fileGroupBox);

    auto hashInput = new QLineEdit(page);
    hashInput->setPlaceholderText("Enter SHA256, MD5, or SHA1...");
    fileLayout->addWidget(new QLabel("Hash:", page));
    fileLayout->addWidget(hashInput);

    auto vtLookupBtn = new QPushButton("Lookup on VirusTotal", page);
    fileLayout->addWidget(vtLookupBtn);

    layout->addWidget(fileGroupBox);

    // Recent Detections Table
    auto tableGroupBox = new QGroupBox("Recent Detections (Last 100)", page);
    auto tableLayout = new QVBoxLayout(tableGroupBox);

    auto detectionTable = new QTableWidget(page);
    detectionTable->setColumnCount(6);
    detectionTable->setHorizontalHeaderLabels({"Time", "Severity", "Rule", "Process", "File/Hash", "Details"});
    detectionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    detectionTable->setSelectionMode(QAbstractItemView::MultiSelection);
    detectionTable->horizontalHeader()->setStretchLastSection(true);
    tableLayout->addWidget(detectionTable);

    layout->addWidget(tableGroupBox);

    layout->addStretch();
    return page;
}

}  // namespace avdashboard
