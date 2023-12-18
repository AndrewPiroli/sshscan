use std::collections::HashMap;
use build_html::{self, HtmlPage, Table, HtmlContainer, ContainerType, Container, Html, TableRow, TableCell, TableCellType};
use crate::{agg_data::{self, AggregatedData}, Host};

struct HostHeader {
    pub title: &'static str,
    pub html_id: &'static str,
    pub data_key: &'static str,
}

macro_rules! hh {
    ($title:expr, $id:expr, $key:expr) => {
        HostHeader {title: $title, html_id: $id, data_key: $key}
    };
}

const HOST_HEADERS: &[HostHeader; 5] = &[
    hh!("Kex Algos", "sshscan-id-kex", "kex_algos"),
    hh!("Host Key Algos", "sshscan-id-hkey", "host_key_algos"),
    hh!("Encryption Algos", "sshscan-id-enc", "encryption_algos"),
    hh!("MAC Algos", "sshscan-id-mac", "mac_algos"),
    hh!("Compression Algos", "sshscan-id-compr", "compression_algos"),
];
const LINK: &str = "https://github.com/AndrewPiroli/sshscan/";
const NAME: &str = "sshscan";
const STYLE: &str = include_str!("style.css");

fn create_page() -> HtmlPage {
    let time = {
        use chrono::prelude::*;
        let time: DateTime<Local> = Local::now();
        time.format("%Y-%m-%dT%H.%M%z").to_string()
    };

    let page = HtmlPage::new()
    .with_title("report")
    .with_style(STYLE);
    
    page
    .with_meta([("name","date"), ("content", time.as_str())])
    .with_meta([("name","generator"), ("content", LINK)])
    .with_meta([("charset", "UTF-8")])
    .with_meta([("name","viewport"), ("content", "width=device-width, initial-scale=1.0, user-scalable=yes")])
    .with_header(1, format!("<a href={LINK}>{NAME}</a> Report - Generated: {time}"))
    .with_header(2, "Hosts")
}

fn build_host_table(rows: &[Vec<String>]) -> Table {
    let mut tab = Table::new().with_attributes([("class", "sshscan-table")]);
    let header_row = {
        let mut header_row = TableRow::new();
        for header in HOST_HEADERS {
            header_row.add_cell(TableCell::new(TableCellType::Header).with_link(format!("#{}", header.html_id), header.title))
        }
        header_row
    };
    tab.add_custom_header_row(header_row);
    for row in rows {
        let mut r = TableRow::new();
        for entry in row {
            if !entry.is_empty() {
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

fn create_host_table(host: &Host) -> Container {
    let mut c = Container::new(ContainerType::Div).with_attributes([("class", "sshscan-htable-outer")]);
    let data = agg_data::wrangle_host_to_table(host);
    for t in data {
        let id = format!("{}:{}", host.addr, t.port);
        let mut inner = Container::new(ContainerType::Div).with_attributes([("class", "sshscan-htable-inner"), ("id", id.as_str())]);
        inner.add_header(3, format!("{} {}", id, t.product.unwrap_or_default()));
        let tab = build_host_table(&t.algos);
        inner.add_table(tab);
        c.add_container(inner);
    }
    c
}

pub fn generate(hosts: &[Host], agg_data: &AggregatedData) -> String {
    if hosts.is_empty() { return create_page().to_html_string(); }
    let mut page = create_page();
    for host_table in hosts.iter().map(create_host_table) {
        page.add_container(host_table);
    }
    for header in HOST_HEADERS {
        page.add_container(create_algo_list(header.title, header.html_id, &agg_data[header.data_key]));
    }
    page.to_html_string()
}

fn create_algo_list(title: &str, title_id: &str, list: &HashMap<String, Vec<&Host>>) -> Container {
    let mut c = Container::new(ContainerType::Div)
    .with_attributes([("class", "sshscan-alist-outer")])
    .with_header_attr(2, title, [("id", title_id)]);
    for algo in list {
        let mut inner = Container::new(ContainerType::UnorderedList);
        for host in algo.1.iter() {
            for host_port in host.port_states.iter() {
                let id = format!("{}:{}", host.addr, host_port.portid);
                inner.add_link(format!("#{id}"), id.as_str());
            }
        }
        c.add_container(Container::new(ContainerType::Div)
        .with_attributes([("class", "sshscan-alist-inner")])
        .with_header_attr(3, format!("{} <span class=\"header-count\">Count: {}</span>", algo.0, algo.1.len()), [("id", format!("algo-{}", algo.0).as_str())])
        .with_container(inner));
    }
    c
}