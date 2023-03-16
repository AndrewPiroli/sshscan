use std::collections::HashMap;

use build_html::{self, HtmlPage, Table, HtmlContainer, ContainerType, Container, Html, TableRow, TableCell, TableCellType};

use crate::{agg_data::{self, AggregatedData}, Host};

const HOST_HEADER: &[&str; 5] = &[
    "Kex Algos",
    "Host Key Algos",
    "Encryption Algos",
    "MAC Algos",
    "Compression Algos",
];

const HEADER_ID: &[&str; 5] = &[
    "sshscan-id-kex",
    "sshscan-id-hkey",
    "sshscan-id-enc",
    "sshscan-id-mac",
    "sshscan-id-compr",
];

const STYLE: &str = include_str!("style.css");

pub fn create_page() -> HtmlPage {
    let time = {
        use chrono::prelude::*;
        let time: DateTime<Local> = Local::now();
        time.format("%Y-%m-%d %H.%M UTC%z").to_string()
    };

    let page = HtmlPage::new()
    .with_title("report")
    .with_style(STYLE);
    
    page
    .with_meta([("date", time.as_str())])
    .with_meta([("generator", "https://github.com/AndrewPiroli/sshscan/")])
    .with_meta([("charset", "UTF-8")])
    .with_meta([("viewport", "width=device-width, initial-scale=1.0, user-scalable=yes")])
}

fn build_host_table(rows: &[Vec<String>]) -> Table {
    let mut tab = Table::new().with_attributes([("class", "sshscan-table")]);
    tab.add_custom_header_row(TableRow::new()
    .with_cell(TableCell::new(TableCellType::Header).with_link(format!("#{}", HEADER_ID[0]), HOST_HEADER[0]))
    .with_cell(TableCell::new(TableCellType::Header).with_link(format!("#{}", HEADER_ID[1]), HOST_HEADER[1]))
    .with_cell(TableCell::new(TableCellType::Header).with_link(format!("#{}", HEADER_ID[2]), HOST_HEADER[2]))
    .with_cell(TableCell::new(TableCellType::Header).with_link(format!("#{}", HEADER_ID[3]), HOST_HEADER[3]))
    .with_cell(TableCell::new(TableCellType::Header).with_link(format!("#{}", HEADER_ID[4]), HOST_HEADER[4])));
    for row in rows {
        let mut r = TableRow::new();
        for entry in row {
            if entry.len() > 0 {
                r.add_cell(TableCell::new(TableCellType::Data).with_link(format!("#algo-{entry}"), entry));
            }
            else {
                r.add_cell(TableCell::new(TableCellType::Data));
            }
        }
        tab.add_custom_body_row(r);
    }
    tab
}

pub fn create_host_table(host: &Host) -> Container {
    let mut c = Container::new(ContainerType::Div).with_attributes([("class", "sshscan-htable-outer")]);
    let data = agg_data::wrangle_host_to_table(host);
    for t in data {
        let id = format!("{}:{}", host.addr, t.0);
        let mut inner = Container::new(ContainerType::Div).with_attributes([("class", "sshscan-htable-inner"), ("id", id.as_str())]);
        inner.add_html(format!("<h3>{id}</h3>"));
        let tab = build_host_table(&t.1);
        inner.add_table(tab);
        c.add_container(inner);
    }
    c
}

pub fn generate(hosts: &[Host], agg_data: &AggregatedData) -> String {
    if hosts.len() < 1 { return create_page().to_html_string(); }
    let mut page = create_page();
    for host_table in hosts.iter().map(create_host_table) {
        page.add_container(host_table);
    }
    page.add_container(create_algo_list(HOST_HEADER[0],HEADER_ID[0], &agg_data.kex_algos));
    page.add_container(create_algo_list(HOST_HEADER[1],HEADER_ID[1], &agg_data.host_key_algos));
    page.add_container(create_algo_list(HOST_HEADER[2],HEADER_ID[2], &agg_data.encryption_algos));
    page.add_container(create_algo_list(HOST_HEADER[3],HEADER_ID[3], &agg_data.mac_algos));
    page.add_container(create_algo_list(HOST_HEADER[4],HEADER_ID[4], &agg_data.compression_algos));
    page.to_html_string()
}

pub fn create_algo_list(title: &str, title_id: &str, list: &HashMap<String, Vec<&Host>>) -> Container {
    let mut c = Container::new(ContainerType::Div)
    .with_attributes([("class", "sshscan-alist-outer")])
    .with_html(format!("<h2 id={title_id}>{title}</h2>"));
    for algo in list {
        let mut inner = Container::new(ContainerType::UnorderedList)
        .with_attributes([("class", "sshscan-alist-inner")]);
        for host in algo.1.iter() {
            for host_port in host.port_states.iter() {
                let id = format!("{}:{}", host.addr, host_port.portid);
                inner.add_link(format!("#{id}"), id.as_str());
            }
        }
        c.add_container(Container::new(ContainerType::Div).with_html(format!("<h3 id=algo-{}>{}</h3>", algo.0, algo.0)).with_container(inner));
    }
    c
}