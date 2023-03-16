use build_html::{self, HtmlPage, Table, HtmlContainer, ContainerType, Container, Html, TableRow};

use crate::{agg_data, Host};

const HOST_HEADER: &[&str; 5] = &[
    "Kex Algos",
    "Host Key Algos",
    "Encryption Algos",
    "MAC Algos",
    "Compression Algos",
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

pub fn create_table_generic(header: &[&str], rows: &[Vec<String>]) -> Table {
    Table::from(rows)
    .with_attributes([("class", "sshscan-table")])
    .with_custom_header_row(TableRow::from(header).with_attributes([("class", "header-row")]))
}

pub fn create_host_table(host: &Host) -> Container {
    let mut c = Container::new(ContainerType::Div).with_attributes([("class", "sshscan-htable-outer")]);
    let data = agg_data::wrangle_host_to_table(host);
    for t in data {
        let id = format!("{}:{}", host.addr, t.0);
        let mut inner = Container::new(ContainerType::Div).with_attributes([("class", "sshscan-htable-inner"), ("id", id.as_str())]);
        inner.add_html(format!("<h3>{id}</h3>"));
        let tab = create_table_generic(HOST_HEADER, &t.1);
        inner.add_table(tab);
        c.add_container(inner);
    }
    c
}

pub fn generate(hosts: &[Host]) -> String {
    if hosts.len() < 1 { return create_page().to_html_string(); }
    let page = create_page().with_container(
        hosts.iter().map(create_host_table).reduce(|mut acc, c|{acc.add_container(c); acc}).unwrap()
    );
    page.to_html_string()
}